import argparse
from socket import *
from utils import (
    SimplexTCPHeader,
    verify_checksum,
    are_flags_set,
    validate_args,
    unpack_segment,
    BETA,
    ALPHA,
    LOGGING_LEVEL,
    MSS,
    MAX_RETRIES,
    INITIAL_TIMEOUT,
    TIME_WAIT,
    TIMEOUT_MULTIPLIER,
)
import random
import logging
import sys
import os
import traceback
import time

logger = logging.getLogger("TCPClient")
# We can set the level to logging.INFO for less verbose logging.
logger.setLevel(LOGGING_LEVEL)

# To log on stdout, we create console handler with a higher log level, format it,
# and add the handler to logger.
ch = logging.StreamHandler()
ch.setLevel(LOGGING_LEVEL)
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
ch.setFormatter(formatter)
logger.addHandler(ch)

# Do the same to log to a file.
fh = logging.FileHandler("tcpclient.log", mode="w")
fh.setLevel(LOGGING_LEVEL)
fh.setFormatter(formatter)
logger.addHandler(fh)


class SimplexTCPClient:
    """
    Implements a Simple TCP client that sends a file to a server using
    UDP sockets over a unreliable channel.
    """

    def __init__(
        self, file, address_of_udpl, port_number_of_udpl, windowsize, ack_port_number
    ):
        """
        Instance variables:
        - file: the file to be transferred
        - proxy_address: the address of the proxy (address, port)
        - windowsize: the size of the sliding window for pipelining segments
        - ack_port_number: the port number to which the client will listen for ACKs
        - socket: the UDP socket used to send and receive segments
        - client_isn: the client's initial sequence number
        - server_isn: the server's initial sequence number
        """
        self.file = file
        self.proxy_address = (address_of_udpl, port_number_of_udpl)
        self.windowsize = windowsize
        self.ack_port_number = ack_port_number

        # Create a UDP socket using IPv4
        self.socket = self.create_and_bind_socket()
        logger.info(f"Socket created and bound to port {self.ack_port_number}")

        # Initialize TCP state variables. Typically, this is done in the
        # three-way handshake, but they are provided here for readability.
        self.client_isn = -1
        self.socket.settimeout(INITIAL_TIMEOUT)
        self.server_isn = -1

        # These will be initialized to their real (estimated) values after the receipt of a valid (non-retransmitted) ACK.
        self.estimated_rtt = -1
        self.dev_rtt = -1

    def create_and_bind_socket(self):
        """
        Create a UDP socket using IPv4
        """
        self.socket = socket(AF_INET, SOCK_DGRAM)
        self.socket.bind(("", self.ack_port_number))
        return self.socket

    def update_timeout_on_rtt(self, sample_rtt: float):
        """
        Updates socket timeout values based on the formulas from RFC 6298.

        TimeoutInterval = EstimatedRTT + 4 * DevRTT, where EstimatedRTT
        is a measure of the average SampleRTT and DevRTT is a measure of the
        variability of the SampleRTT. Both are weighted averages whose weights
        can be adjusted in the headers.

        EstimatedRTT = BETA * EstimatedRTT + (1 - BETA) * SampleRTT
        DevRTT = (1 - ALPHA) * DevRTT + ALPHA * |SampleRTT - EstimatedRTT|
        """
        # Upon the receipt of the first valid ACK, the estimated and dev RTTs
        # need to be initialized as follows. Note that we check if the values
        # are less than 0 because the values are initialized to -1 in both
        # the client and server.
        if self.estimated_rtt < 0 and self.dev_rtt < 0:
            self.estimated_rtt = sample_rtt
            self.dev_rtt = sample_rtt / 2

        # Set timeout interval according to RFC 6298.
        self.estimated_rtt = BETA * self.estimated_rtt + (1 - BETA) * sample_rtt
        self.dev_rtt = (1 - ALPHA) * self.dev_rtt + ALPHA * abs(
            sample_rtt - self.estimated_rtt
        )
        timeout_interval = self.estimated_rtt + (4 * self.dev_rtt)
        self.socket.settimeout(timeout_interval)
        logger.info(
            f"New SampleRTT: Updated timeout interval to {timeout_interval} seconds"
        )
        return

    def update_timeout_on_timeout(self):
        """
        Updates socket timeout values by TIMEOUT_MULTIPLIER when a timeout occurs.

        Traditionally, this multiplier set to twice the timeout interval, but we
        allow flexibility to tweak this to evaluate performance. Greater
        timeout intervals mean that lost packets will not be retransmitted quickly,
        but shorter timeout intervals mean that there might be unnecessary retransmissions.
        """
        timeout_interval = self.socket.gettimeout()
        self.socket.settimeout(timeout_interval * TIMEOUT_MULTIPLIER)
        logger.info(
            f"Timed out: updated timeout interval to {timeout_interval * TIMEOUT_MULTIPLIER} seconds"
        )
        return

    def establish_connection(self):
        """
        Establishes a connection with the destination address.
        1. Send SYN segment with random sequence number and no payload.
        2. Receive SYNACK segment from server.
        3. Send ACK segment with payload containing the file_size of the file to be transferred.
        """
        logger.info(f"Establishing connection with server...")
        self._send_syn_and_wait_for_synack()

        # At this point, we have received a SYNACK segment from the server. After the client
        # sends the ACK segment, the client enters the CONNECTION_ESTABLISHED state. However,
        # because the server doesn't enter the CONNECTION_ESTABLISHED state until it receives
        # this just-sent ACK, there is a brief period of time where the connection is half-open.
        # During this time, this packet is still vulnerable to being dropped. To prevent a half-open
        # connection and to provide the server with additional data needed for the file transfer,
        # the client sends the file_size in the ACK segment and waits for an ACK from the server
        # with the same timeout mechanism as any other packet.
        self._send_ack_with_filesize()
        logger.info(f"====================== ESTABLISHED! ==========================")
        return

    def send_fin(self):
        """
        The only case where the client initiates a connection termination is when the client
        has retransmitted a segment MAX_RETRIES times.

        If a segment's retransmission limit is hit, the client will:
        - Send a FIN segment to the server.
        - Wait for an ACK from the server.
        - Wait for the server to send its own FIN segment and send an ACK.
        - Wait for TIME_WAIT seconds
        - Closing the connection.
        """
        # Send a FIN segment to the server
        self._send_fin_and_wait_for_ack()

        # Wait for the server to send its own FIN segment and send an ACK.
        self._wait_for_fin_and_send_ack()

        # Wait for TIME_WAIT seconds before closing the connection.
        time.sleep(TIME_WAIT)

        # Deallocate resources.
        logger.info(f"Closing connection. Goodbye...")
        self.socket.close()
        sys.exit(0)

    def _send_fin_and_wait_for_ack(self):
        """
        Helper function for send_fin
        """
        fin_segment = self.create_tcp_segment(
            payload=b"",
            seq_num=0,
            ack_num=0,
            flags={"FIN"},
        )

        # Transmit FIN segments until we receive an FINACK from the server, retransmitting
        # if the socket times out.
        retry_count = 0
        for _ in range(MAX_RETRIES):
            retry_count += 1

            self.socket.sendto(fin_segment, self.proxy_address)
            logger.info(f"Entered FIN_WAIT_1 state: sent FIN segment to server.")

            try:
                fin_ack, _ = self.socket.recvfrom(self.windowsize)
                _, _, flags, _, _ = unpack_segment(fin_ack)

                if not verify_checksum(fin_ack) or not are_flags_set(
                    flags, {"ACK", "FIN"}
                ):
                    logger.error(f"Verification failed. Dropping packet...")
                    continue

                logger.info(f"Entered FIN_WAIT_2 state: received ACK from server.")
                break
            except timeout:
                self.update_timeout_on_timeout()
                logger.info(
                    f"Timeout occurred while waiting for FINACK. Retransmitting FIN segment..."
                )
                continue
            except Exception as e:
                logger.warning(f"Exception occurred while terminating connection {e}")
                logger.warning(f"Traceback: {traceback.format_exc()}")
                continue

        if retry_count >= MAX_RETRIES:
            logger.warning(
                f"Maximum number of retries reached while sending FIN. Aborting..."
            )
            exit(0)
        return

    def _wait_for_fin_and_send_ack(self):
        """
        Helper function for the second leg of send_fin()
        """
        # Note: we are guaranteed to receive a FIN from
        # the server per the assignment spec. Otherwise, we can
        # avoid infinitely waiting by changing the infinite loop to
        # a loop with a maximum number of retries like in _send_fin_and_wait_for_ack().
        while True:
            try:
                fin_segment, _ = self.socket.recvfrom(self.windowsize)

                # Verify this is a FIN segment.
                _, _, flags, _, _ = unpack_segment(fin_segment)
                if not verify_checksum(fin_segment) and not are_flags_set(
                    flags, {"FIN"}
                ):
                    logger.error(f"Verification failed. Dropping packet...")
                    continue

                # Correctly received FIN segment from server. Send ACK back. Note that we don't
                # need to retransmit this ACK because the server will close its side of the
                # connection upon sending its FIN segment.
                logger.info(
                    f"Entered TIME_WAIT state: received FIN from server and sending ACK back..."
                )
                ack_segment = self.create_tcp_segment(
                    payload=b"",
                    seq_num=0,
                    ack_num=0,
                    flags={"ACK", "FIN"},
                )
                self.socket.sendto(ack_segment, self.proxy_address)
                break
            except timeout:
                self.update_timeout_on_timeout()
                logger.error(
                    f"Timeout occurred while waiting for FIN. Waiting longer..."
                )
                continue
        return

    def respond_to_fin(self):
        """
        Called when the client receives a FIN from the server.

        The client will:
        - Receive the FIN (invoking this function) and respond with an ACK --> enters CLOSE_WAIT state.
        - Send its own FIN --> enters LAST_ACK state
        - Receive an ACK and send nothing --> CLOSED state
        """
        fin_ack = self.create_tcp_segment(
            payload=b"", seq_num=0, ack_num=0, flags={"FIN", "ACK"}
        )

        # This FINACK may get lost, but the client has no way of knowing if
        # if gets lost because the server will only respond after the client
        # sends another message: the last FIN.
        # In both cases (where the FINACK gets dropped), we send the FIN.
        # In the case it gets lost, the server will handle receiving the FIN
        # but not the previous FINACK.
        self.socket.sendto(fin_ack, self.proxy_address)
        logger.info(f"Entered CLOSE_WAIT state: sent FINACK to server. Sending FIN...")

        # Although the textbook specifies that the non-initiator's side of the
        # TCP connection should be closed after sending the last FIN, because the
        # FIN segment could be dropped, we wait for an ACK from the server
        # to ensure that the server has received the FIN segment.
        fin = self.create_tcp_segment(payload=b"", seq_num=0, ack_num=0, flags={"FIN"})
        retry_count = 0
        for _ in range(MAX_RETRIES):
            retry_count += 1

            self.socket.sendto(fin, self.proxy_address)
            try:
                ack, _ = self.socket.recvfrom(self.windowsize)
                _, _, flags, _, _ = unpack_segment(ack)

                if not verify_checksum(ack) or not are_flags_set(flags, {"ACK", "FIN"}):
                    logger.error(
                        f"Verification failed. Dropping packet with flags {flags}"
                    )
                    continue

                logger.info(f"Received FINACK from server.")
                break
            except timeout:
                self.update_timeout_on_timeout()
                logger.info(
                    f"Timeout occurred while waiting for FINACK. Retransmitting FIN segment..."
                )

        if retry_count >= MAX_RETRIES:
            logger.info(
                f"Waited too long for FINACK. Aborting to avoid half-open connections..."
            )

        # Receive a FINACK from the server or the FIN segment has hit its retransmission limit. Either way, we can exit.
        logger.info(f"Goodbye...")
        sys.exit(0)

    def send_file_gbn(self):
        """
        Go-Back-N implementation of sending a file to the server.
        """
        # Send base denotes the sequence number of the oldest unacknowledged segment.
        # This is initialized to TODO
        # Window is a list of segments that have been sent but not yet acknowledged, along with
        # the number of times they have been retransmitted. num_retries is initialized to 0.
        # When a segment hits max_retries, send_fin() is called to terminate the connection as
        # the network is probably pretty ass at the moment.
        #   Format: [(segment, num_retries), ...]
        send_base = self.client_isn + 4 + 1
        next_seq_num = self.client_isn + 4 + 1
        num_dup_acks = 0
        window = []

        # Variables for measuring SampleRTT to readjust the timeout interval.
        # We keep track of measuring_rtt to only measure once per round trip (once per window),
        # seq_num_rtt so we can check if it has been retransmitted (to cancel the rtt calculation)
        # and to stop the timer correctly, and start for the start of the timer so (end-start) = SampleRTT
        measuring_rtt = False
        seq_num_rtt = -1
        start = -1
        logger.info(f"Sending file {self.file} to server...")
        with open(self.file, "rb") as file:

            sent_new_payload = True
            done_reading = False
            while True:

                # Don't increment the file pointer unless we are sending a new payload.
                if sent_new_payload and not done_reading:
                    payload = file.read(MSS)

                # Payload will be empty when we reach the end of the file.
                if not payload:
                    done_reading = True
                    logger.info(f"Reached end of file. Sending outstanding segments...")

                # Fill the window with segments until it is full and send all segments.
                if (
                    next_seq_num < send_base + (self.windowsize // MSS)
                    and not done_reading
                ):
                    segment = self.create_tcp_segment(
                        payload=payload,
                        seq_num=next_seq_num,
                        ack_num=0,  # ack num does not matter for data segments
                        flags=set(),
                    )

                    # We also have to measure SampleRTTs while pipelining. Only compute the
                    # sample RTT for one of the segments in the window and cancel the
                    # timer if it needs to be retransmitted.
                    if measuring_rtt == False:
                        measuring_rtt = True
                        seq_num_rtt = next_seq_num
                        start = time.time()

                    self.socket.sendto(segment, self.proxy_address)
                    sent_new_payload = True
                    window.append((segment, 0))
                    next_seq_num += 1

                else:  # Window is full.
                    sent_new_payload = False
                    try:
                        ack, _ = self.socket.recvfrom(self.windowsize)
                        _, ack_num, flags, _, _ = unpack_segment(ack)
                        if not verify_checksum(ack):
                            logger.error(f"Verification failed. Dropping packet...")
                            continue
                        # Received an ACK for a segment in the window. If we are measuring the
                        # SampleRTT, check if the ACK is for the segment we are measuring and
                        # that it has not been retransmitted. If so, cancel the timer and
                        if ack_num >= send_base and are_flags_set(flags, {"ACK"}):
                            logger.debug(
                                f"Received ACK {ack_num}, measuring_rtt is {measuring_rtt}, seq_num_rtt is {seq_num_rtt}, window[0][1] is {window[0][1]}"
                            )
                            if (
                                measuring_rtt
                                and seq_num_rtt == ack_num
                                and window[0][1] == 0
                            ):
                                measuring_rtt = False
                                end = time.time()
                                sample_rtt = end - start
                                logger.debug(
                                    f"Received ACK {ack_num}. SampleRTT measured: {sample_rtt} seconds."
                                )
                                self.update_timeout_on_rtt(sample_rtt)
                                seq_num_rtt = -1
                                start = -1
                            # If it has been retransmitted, cancel the timer. We just won't have
                            # an accurate SampleRTT for this round trip.
                            elif (
                                measuring_rtt
                                and seq_num_rtt == ack_num
                                and window[0][1] > 0
                            ):
                                measuring_rtt = False
                                seq_num_rtt = -1
                                start = -1
                                logger.debug(
                                    f"Received ACK {ack_num}. SampleRTT not measured because segment was retransmitted."
                                )

                            # Either way, we got a valid ACK for a segment in our window so we can move the window forward.
                            logger.debug(
                                f"Received ACK {ack_num}. Moving window forward..."
                            )
                            logger.debug(
                                f"removing segment with payload {window[0][0][20:]}"
                            )
                            window.pop(0)
                            send_base = ack_num + 1

                        elif are_flags_set(flags, {"FIN"}):
                            logger.info(
                                "Received FIN from server. Closing connection..."
                            )
                            self.respond_to_fin()
                        else:
                            logger.info(f"Received duplicate ACK...")
                            logger.debug(
                                f"Received duplicate ACK with ack_num {ack_num}. Expecting ack_num {send_base}."
                            )
                            num_dup_acks += 1

                            # Part of fast Retransmit. If we receive 3 duplicate ACKs, then resend the segment
                            # with the lowest sequence number in the window.
                            if num_dup_acks == 3:
                                logger.info(
                                    f"Received 3 duplicate ACKs. Resending segment with seq_num {send_base}"
                                )
                                segment, num_retries = window[0]
                                window[0] = (segment, 0)
                                self.socket.sendto(segment, self.proxy_address)
                                num_dup_acks = 0

                    except timeout:
                        self.update_timeout_on_timeout()
                        # If the timer expires, then resend all segments in the window and increment
                        # their retry count.
                        # If the segment hit the retransmission limit for a packet, then terminate
                        # the connection.
                        for i in range(len(window)):
                            segment, num_retries = window[i]
                            num_retries += 1

                            if num_retries >= MAX_RETRIES:
                                logger.warning(
                                    f"Max retransmissions reached. Terminating connection..."
                                )
                                self.send_fin()
                            window[i] = (segment, num_retries)

                        # Otherwise, resend all the segments and increment their retry counts
                        logger.info(f"Timer expired. Resending segments in window...")
                        for segment, num_retries in window:
                            logger.debug(
                                f"resending segment with payload {segment[20:]}"
                            )
                            self.socket.sendto(segment, self.proxy_address)

    def _send_ack_with_filesize(self):
        """
        Send an ACK segment with the file size to the server and wait for an ACK from the server.

        This mechanism is to prevent a half-open connection if the last ACK of the three-way
        handshake gets lost. While the server will timeout waiting for its SYNACK to be ACK'd,
        the client will think that the connection is established and start sending data. By waiting
        for an additional ACK, we can ensure that the connection is fully established before
        sending file data.
        """
        # Create a TCP segment with the ACK flag set and the file size as the payload.
        file = open(self.file, "rb")
        file_size = os.path.getsize(self.file)
        payload = file_size.to_bytes(4, byteorder="big")
        file.close()

        segment = self.create_tcp_segment(
            payload=payload,
            seq_num=(self.client_isn + len(payload)),
            ack_num=(self.server_isn + 1),
            flags={"ACK"},
        )

        # Keep track of the number of retries so we can differentiate between a successful
        # retransmission and reaching the maximum number of retries.
        retry_count = 0

        for _ in range(MAX_RETRIES):
            retry_count += 1

            # Try measuring a sample RTT.
            start = time.time()
            self.socket.sendto(segment, self.proxy_address)
            logger.info(
                f"Entered CONNECTION ESTABLISHED state: sent ACK with file size"
            )

            try:
                ack, _ = self.socket.recvfrom(self.windowsize)

                seq_num, ack_num, flags, _, _ = unpack_segment(ack)
                logger.info(
                    f"received segment with ack number {ack_num}, flags {flags}, and sequence number {seq_num}"
                )

                # TODO: make sure logging level sare consistent
                if not verify_checksum(ack):
                    logger.error(f"Checksum verification failed.")
                    continue
                if not are_flags_set(flags_byte=flags, expected_flags={"ACK"}):
                    logger.error(f"Flag verification failed.")
                    continue
                # Check if the ACK number is correct.
                if ack_num != self.client_isn + len(payload) + 1:
                    logger.error(
                        f"ACK number is incorrect, expected {self.client_isn + len(payload) + 1}, received: {ack_num}"
                    )
                    continue

                # Only update the timeout value if we have a valid sample RTT.
                if retry_count == 1:
                    sample_rtt = time.time() - start
                    self.update_timeout_on_rtt(sample_rtt)
                break
            except timeout:
                self.update_timeout_on_timeout()
                logger.info(f"Timeout occurred while finishing handshake.")
                continue
            except Exception as e:
                logger.warning(f"Exception occurred while finishing handshake: {e}")
                logger.warning(f"Traceback: {traceback.format_exc()}")
                continue

        if retry_count >= MAX_RETRIES:
            logger.warning(f"Maximum number of retries reached...")
            self.send_fin()

        return

    def _send_syn_and_wait_for_synack(self):
        """
        Send SYN segment with no payload, SYN flag set, and random sequence number.
        Generate random sequence number, which will be the client's ISN that will be incremented
        for each segment sent.
        """
        self.client_isn = random.randint(0, 2**32 - 1)
        logger.debug(f"Client ISN: {self.client_isn}")

        # Create SYN segment with no payload, SYN flag set, and random sequence number. We
        # set the ack number to 0 because we are not acknowledging any data from the server.
        syn_segment = self.create_tcp_segment(
            payload=b"", seq_num=self.client_isn, ack_num=0, flags={"SYN"}
        )

        # Keep track of the number of retries so we can differentiate between a successful
        # retransmission and reaching the maximum number of retries.
        retry_count = 0

        for _ in range(MAX_RETRIES):
            retry_count += 1

            start = time.time()
            self.socket.sendto(syn_segment, self.proxy_address)
            logger.info(f"Entered SYN_SENT state: sent SYN segment to server")

            try:
                synack_segment, _ = self.socket.recvfrom(self.windowsize)

                seq_num, ack_num, flags, _, _ = unpack_segment(synack_segment)
                logger.info(
                    f"received segment with seq number {seq_num}, and flags {flags}"
                )

                if not verify_checksum(synack_segment):
                    logger.error(f"Checksum verification failed.")
                    continue
                if not are_flags_set(flags_byte=flags, expected_flags={"SYN", "ACK"}):
                    logger.error(
                        f"Received segment does not have SYN and ACK flag set."
                    )
                    continue

                # Check if the ACK number is correct.
                if ack_num != self.client_isn + 1:
                    logger.error(
                        f"ACK number is incorrect, expected {self.client_isn + 1}, received: {ack_num}"
                    )
                    continue

                # Stash the server's ISN for future use. This will be used to ACK the server's segments.
                self.server_isn = seq_num

                # Only use the SampleRTT measured if it is not a retransmission.
                if retry_count == 1:
                    sample_rtt = time.time() - start
                    self.update_timeout_on_rtt(sample_rtt)

                logger.info(
                    f"Received SYNACK segment from server with server ISN: {self.server_isn}"
                )
                break
            except timeout:
                self.update_timeout_on_timeout()
                logger.info(f"Timeout occurred while receiving SYNACK segment")
                continue
            except Exception as e:
                logger.warning(
                    f"Exception occurred while receiving SYNACK segment: {e}"
                )
                logger.warning(f"Traceback: {traceback.format_exc()}")
                continue

        if retry_count >= MAX_RETRIES:
            logger.warning(f"Maximum number of retries reached. Aborting...")
            sys.exit(0)

        return self.server_isn

    def create_tcp_segment(self, payload, seq_num, ack_num, flags=set()):
        """
        Creates a TCP segment with the given payload and flags.

        :param payload: payload to be sent to the server
        :param flags: set of flags to be set in the TCP header
        """
        logger.debug(
            f"Sending segment with payload {payload}, flags {flags}, ack number {ack_num}, seq number {seq_num}"
        )

        # Create the segment without the checksum.
        tcp_header = SimplexTCPHeader(
            src_port=self.ack_port_number,
            dest_port=self.proxy_address[1],
            seq_num=seq_num,
            ack_num=ack_num,
            recv_window=self.windowsize,
            flags=flags,
        )

        # Attach the TCP header to payload.
        tcp_segment = tcp_header.make_tcp_segment(payload)

        return tcp_segment

    def run(self):
        """
        Run the TCP client to send the file to the server.
        """
        self.establish_connection()
        self.send_file_gbn()
        return


def main():
    """
    Entry point for the TCP client.
    """
    parser = argparse.ArgumentParser(description="Bootleg TCP implementation over UDP")
    parser.add_argument("file", type=str, help="file that client reads data from")
    parser.add_argument("address_of_udpl", type=str, help="emulator's address")
    parser.add_argument("port_number_of_udpl", type=int, help="emulator's port number")
    parser.add_argument("windowsize", type=int, help="window size in bytes")
    parser.add_argument("ack_port_number", type=int, help="port number for ACKs")
    args = parser.parse_args()

    logger.info("=============================")
    logger.info("TCPClient Parameters:")
    for arg in vars(args):
        logger.info(f"{arg}: {getattr(args, arg)}")
    logger.info("==============================")

    # Validate command line arguments before allocating TCP state variables.
    if not validate_args(args, is_client=True):
        logger.error("Invalid arguments. Aborting...")
        sys.exit(1)

    # Create and run the TCP client instance to transfer the file to the server.
    tcp_client = SimplexTCPClient(
        args.file,
        args.address_of_udpl,
        args.port_number_of_udpl,
        args.windowsize,
        args.ack_port_number,
    )
    tcp_client.run()
    return


if __name__ == "__main__":
    main()
