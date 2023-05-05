import argparse
from socket import *
from utils import (
    SimplexTCPHeader,
    verify_checksum,
    verify_flags,
    validate_args,
    unpack_segment,
    MSS,
    MAX_RETRIES,
    INITIAL_TIMEOUT,
)
import random
import logging
import sys
import os
import traceback
import time

logger = logging.getLogger("TCPClient")
logger.setLevel(logging.INFO)

# To log on stdout, we create console handler with a higher log level, format it,
# and add the handler to logger.
ch = logging.StreamHandler()
ch.setLevel(logging.INFO)
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
ch.setFormatter(formatter)
logger.addHandler(ch)

# Do the same to log to a file.
fh = logging.FileHandler("tcpclient.log", mode="w")
fh.setLevel(logging.INFO)
fh.setFormatter(formatter)
logger.addHandler(fh)

# The client waits TIME_WAIT seconds before closing the connection after receiving
# a FIN from the server.
# Typical values are 30 seconds, 1 minute, and 2 minutes.
TIME_WAIT = 30


class SimplexTCPClient:
    """ """

    def __init__(
        self, file, address_of_udpl, port_number_of_udpl, windowsize, ack_port_number
    ):
        self.file = file
        # self.proxy_address = ("0.0.0.0", 4444) For testing
        self.proxy_address = (address_of_udpl, port_number_of_udpl)
        self.windowsize = windowsize
        self.ack_port_number = ack_port_number

        # Create a UDP socket using IPv4
        self.socket = self.create_and_bind_socket()
        logger.info(f"Socket created and bound to port {self.ack_port_number}")

        # Initialize TCP state variables. Typically, this is done in the
        # three-way handshake, but they are provided here for readability.
        self.client_isn = 0
        self.socket.settimeout(INITIAL_TIMEOUT)
        self.server_isn = -1
        self.expected_ack_num = -1

    def create_and_bind_socket(self):
        """
        Create a UDP socket using IPv4
        """
        self.socket = socket(AF_INET, SOCK_DGRAM)
        self.socket.bind(("", self.ack_port_number))
        return self.socket

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
        - Wait for TIME_WAIT seconds before closing the connection.
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
            retry_count +=1
            
            self.socket.sendto(fin_segment, self.proxy_address)
            logger.info(f"Entered FIN_WAIT_1 state: sent FIN segment to server.")

            try:
                fin_ack, _ = self.socket.recvfrom(
                    2048
                )  # do i change this to windowsize?
                _, _, flags, _, _ = unpack_segment(fin_ack)

                if not verify_checksum(fin_ack) or not verify_flags(
                    flags, {"ACK", "FIN"}
                ):
                    logger.error(f"Verification failed. Dropping packet...")
                    continue

                logger.info(f"Entered FIN_WAIT_2 state: received ACK from server.")
                break
            except timeout:
                logger.info(
                    f"Timeout occurred while waiting for FINACK. Retransmitting FIN segment..."
                )
                continue
            except Exception as e:
                logger.warning(f"Exception occurred while terminating connection {e}")
                logger.error(f"Traceback: {traceback.format_exc()}")
                continue
        
        if retry_count >= MAX_RETRIES:
            logger.error(f"Maximum number of retries reached while sending FIN. Aborting...")
            exit(1)
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
                fin_segment = self.socket.recvfrom(2048)

                # Verify this is a FIN segment.
                _, _, flags, _, _ = unpack_segment(fin_segment)
                if not verify_checksum(fin_segment) and not verify_flags(
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
                    flags={"ACK"},
                )
                self.socket.sendto(ack_segment, self.proxy_address)
                break
            except timeout:
                logger.error(
                    f"Timeout occurred while waiting for FIN. Waiting longer..."
                )
                continue
        return

    def send_file_gbn(self):
        """
        Go-Back-N sender.
        """
        # Send base denotes the sequence number of the oldest unacknowledged segment.
        # This is initialized to TODO
        send_base = self.client_isn + 4 + 1
        next_seq_num = self.client_isn + 4 + 1
        window = []

        # TODO: change window to list of tuples (segment, num_retries)
        # Format: {segment: num_retries}. This is the window of segments that have been sent but not yet acknowledged.
        # When a segment hits max_retries, send_fin() to terminate the connection as
        # the network is really ass then.

        logger.info(f"Sending file {self.file} to server...")
        with open(self.file, "rb") as file:

            sent_new_payload = True
            done_reading = False
            while True:

                # Don't increment the file pointer unless we are sending a new payload.
                if sent_new_payload and not done_reading:
                    payload = file.read(MSS)

                # logger.info(f"current payload: {payload}")

                # Payload will be empty when we reach the end of the file.
                if not payload:
                    logger.info(f"Reached end of file. Sending outstanding segments...")

                # Fill the window with segments until it is full and send all segments.
                if next_seq_num < send_base + (self.windowsize // MSS):
                    logger.info(
                        f"Condition 1: {next_seq_num} < {send_base} + {self.windowsize // MSS}"
                    )
                    # Send the next segment
                    segment = self.create_tcp_segment(
                        payload=payload,
                        seq_num=next_seq_num,
                        ack_num=0,  # ack num does not matter for data segments
                        flags=set(),
                    )

                    self.socket.sendto(segment, self.proxy_address)
                    sent_new_payload = True
                    window.append(segment)
                    next_seq_num += 1
                else:
                    sent_new_payload = False
                    try:
                        ack, _ = self.socket.recvfrom(2048)
                        _, ack_num, flags, _, _ = unpack_segment(ack)
                        if ack_num >= send_base:
                            logger.info(
                                f"Received ACK {ack_num}. Moving window forward to [{ack_num + 1}, {next_seq_num - 1}]"
                            )
                            logger.info(
                                f"removing segment with payload {window[0][20:]}"
                            )
                            window.pop(0)
                            send_base = ack_num + 1
                        else:
                            logger.info(
                                f"Received duplicate ACK with ack_num {ack_num}. Expecting ack_num {send_base}."
                            )
                    except timeout:
                        # If the timer expires, then resend all segments in the window.
                        logger.warning(
                            f"Timeout expired. Resending all segments in window [send_base, nextseqnum -1]: [{send_base}, {next_seq_num - 1}]..."
                        )
                        for segment in window:
                            logger.info(
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
            self.socket.sendto(segment, self.proxy_address)
            logger.info(
                f"Entered CONNECTION ESTABLISHED state: sent ACK with file size"
            )

            try:
                ack, server_address = self.socket.recvfrom(2048)

                seq_num, ack_num, flags, _, _ = unpack_segment(ack)
                logger.info(
                    f"received segment with ack number {ack_num}, flags {flags}, and sequence number {seq_num}"
                )

                # TODO: make sure logging level sare consistent
                if not verify_checksum(ack):
                    logger.error(f"Checksum verification failed.")
                    continue
                if not verify_flags(flags_byte=flags, expected_flags={"ACK"}):
                    logger.error(f"Flag verification failed.")
                    continue
                # Check if the ACK number is correct.
                if ack_num != self.client_isn + len(payload) + 1:
                    logger.error(
                        f"ACK number is incorrect, expected {self.client_isn + len(payload) + 1}, received: {ack_num}"
                    )
                    continue

                break
            except timeout:
                # TODO: increase timeout acc. to formula in book.
                logger.info(f"Timeout occurred while finishing handshake.")
                continue
            except Exception as e:
                logger.warning(f"Exception occurred while finishing handshake: {e}")
                logger.error(f"Traceback: {traceback.format_exc()}")
                continue

        if retry_count >= MAX_RETRIES:
            logger.error(f"Maximum number of retries reached...")
            self.send_fin()

        return

    def _send_syn_and_wait_for_synack(self):
        """
        Send SYN segment with no payload, SYN flag set, and random sequence number.
        Generate random sequence number, which will be the client's ISN that will be incremented
        for each segment sent.
        """
        self.client_isn = random.randint(0, 2**32 - 1)
        # self.client_isn = 0
        logger.info(f"Client ISN: {self.client_isn}")

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
            self.socket.sendto(syn_segment, self.proxy_address)
            logger.info(f"Entered SYN_SENT state: sent SYN segment to server")

            try:
                # TODO: change buffer size

                synack_segment, server_address = self.socket.recvfrom(2048)

                seq_num, ack_num, flags, _, _ = unpack_segment(synack_segment)
                logger.info(
                    f"received segment with seq number {seq_num}, and flags {flags}"
                )

                if not verify_checksum(synack_segment):
                    logger.error(f"Checksum verification failed.")
                    continue
                if not verify_flags(flags_byte=flags, expected_flags={"SYN", "ACK"}):
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
                logger.info(
                    f"Received SYNACK segment from server with server ISN: {self.server_isn}"
                )
                break
            except timeout:
                # TODO: increase timeout acc. to formula in book.
                logger.info(f"Timeout occurred while receiving SYNACK segment")
                continue
            except Exception as e:
                logger.warning(
                    f"Exception occurred while receiving SYNACK segment: {e}"
                )
                logger.error(f"Traceback: {traceback.format_exc()}")
                continue

        if retry_count >= MAX_RETRIES:
            logger.error(f"Maximum number of retries reached. Aborting...")
            self.send_fin()

        return self.server_isn

    def create_tcp_segment(self, payload, seq_num, ack_num, flags=set()):
        """
        Creates a TCP segment with the given payload and flags.

        :param payload: payload to be sent to the server
        :param flags: set of flags to be set in the TCP header
        """
        logger.info(
            f"Sending segment with payload {payload}, flags {flags}, ack number {ack_num}, seq number {seq_num}"
        )

        # Create the segment without the checksum.
        tcp_segment = SimplexTCPHeader(
            src_port=self.ack_port_number,
            dest_port=self.proxy_address[1],
            seq_num=seq_num,
            ack_num=ack_num,
            recv_window=self.windowsize,
            flags=flags,
        )

        # Attach the TCP header to payload.
        tcp_header = tcp_segment.make_tcp_header(payload)

        # TODO: naming is a bit confusing. tcp_header is actually the entire segment.
        return tcp_header

    def shutdown(self):
        """
        Close all open sockets and files.
        """
        self.socket.close()
        # TODO close file, maybe instance variable for file?

        logger.info(f"Shutting down client...")
        return

    def run(self):
        self.establish_connection()
        self.send_file_gbn()

        # After the client is finished sending the file, it sends a FIN segment to the server.
        # it will keep sending the FIN segment until it receives an ACK.
        # self.send_fin()
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

    print("=============================")
    print("TCPClient Parameters:")
    for arg in vars(args):
        print(f"{arg}: {getattr(args, arg)}")
    print("==============================")

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
