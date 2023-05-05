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
import logging
import struct
import traceback
import random
import sys

logger = logging.getLogger("TCPServer")
logger.setLevel(logging.INFO)

# To log on stdout, we create console handler with a higher log level, format it,
# and add the handler to logger.
ch = logging.StreamHandler()
ch.setLevel(logging.INFO)
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
ch.setFormatter(formatter)
logger.addHandler(ch)

# Do the same to log to a file.
fh = logging.FileHandler("tcpserver.log")
fh.setLevel(logging.INFO)
fh.setFormatter(formatter)
logger.addHandler(fh)


class SimplexTCPServer:
    """ """

    def __init__(self, file, listening_port, address_for_acks, port_for_acks):
        self.file = file
        self.listening_port = listening_port
        self.client_address = (address_for_acks, port_for_acks)

        self.socket = self.create_and_bind_socket()
        self.socket.settimeout(INITIAL_TIMEOUT)
        logger.info(f"Socket created and bound to port {self.listening_port}")

        self.client_isn = -1
        self.server_isn = 0
        self.expected_ack_num = -1
        # self.server_isn = random.randint(0, 2**32 - 1)
        return

    def create_and_bind_socket(self):
        """
        Creates a UDP socket and binds it to the listening port.
        """
        self.socket = socket(AF_INET, SOCK_DGRAM)
        self.socket.bind(("", self.listening_port))
        return self.socket

    def create_tcp_segment(self, payload, seq_num, ack_num, flags):
        """
        Creates a TCP segment with the given payload and flags.

        :param payload: payload to be sent to the server
        :param flags: set of flags to be set in the TCP header
        """
        # Create the segment without the checksum. Increment the ack number,
        # indicating that the server is expecting the ack_num + 1 byte next
        logger.info(
            f"Sending segment with ack number {ack_num}, seq number {seq_num}, and flags {flags}"
        )

        tcp_segment = SimplexTCPHeader(
            src_port=self.listening_port,
            dest_port=self.client_address[1],
            seq_num=seq_num,
            ack_num=ack_num,
            recv_window=10,  # TODO: change this
            flags=flags,
        )

        # Attach the TCP header to payload.
        tcp_header = tcp_segment.make_tcp_header(payload)

        # TODO: change naming. This is actually the segment, not just the header.
        return tcp_header

    def receive_file_gbn(self):
        """
        Go-Back-N receiver. The receiver will keep track of the
        expected sequence number to receive next: nextseqnum

        Out of order and corrupted packets will be discarded. In the
        case of 1) receiving a new packet and 2) receiving a corrupted/OOO
        packet, the receiver will send an ACK with the last in-order packet
        correctly received, resulting in duplicate ACKs (acks for packets
        the server has already ACkd for case 2.
        """
        # File name will be "received_file" + file extension
        # file_extension = self.file.split(".")[-1]
        # file_name = "recvd_file." + file_extension
        file_name = "recvd_file"

        # Initialize GBN variables
        next_seq_num = self.client_isn + 4 + 1
        # next_expected_seq_num = self.client_isn + 2
        last_byte_recvd = 0

        # Open the new file for writing. Keep writing data to the file until
        # the server has received all the data from the client.
        logger.info(f"Receiving file {self.file}...")
        with open(file_name, "wb") as file:
            while last_byte_recvd < self.file_size:
                try:
                    segment, client_address = self.socket.recvfrom(
                        2048
                    )  # catch timeout
                except timeout:
                    logger.warning(f"Timeout occurred receiving data. Retrying...")
                    continue

                # Received a segment! Note that this payload is padded, which will
                # later be stripped by the verify_checksum function.
                seq_num, ack_num, flags, recv_window, payload = unpack_segment(segment)
                logger.info(f"payload received: {payload}")

                # If the packet is in order and uncorrupted, write the payload to the file
                # increment nextseqnum, send ACK saying nextseqnum was received. If the packet
                # is out of order or corrupted, send ACK saying last in-order packet was received.
                ack = None
                if verify_checksum(segment) and seq_num == next_seq_num:
                    last_byte_recvd += len(payload)

                    # Write the payload to the file
                    file.write(payload)
                    ack = self.create_tcp_segment(
                        payload=b"", seq_num=0, ack_num=next_seq_num, flags={"ACK"}
                    )
                    next_seq_num += len(payload)
                else:
                    logger.warning(
                        f"Received corrupted or out of order segment with seq num {seq_num} and payload {payload} \n Sending dup ACK for seq num {next_seq_num - 1}"
                    )
                    ack = self.create_tcp_segment(
                        payload=b"",
                        seq_num=0,  # seq_num doesn't matter for ACKs
                        ack_num=(next_seq_num - 1),
                        flags={"ACK"},
                    )

                self.socket.sendto(ack, self.client_address)

        logger.info(f"last payload: {payload}")
        logger.info(f"File received. Closing connection...")
        return

    def establish_connection(self):
        """
        Establishes a connection with the client address via the following steps:
        1. Receive SYN segment with random sequence number and no payload.
        2. Send SYNACK segment to client with random sequence number, SYN and ACK fields, and no payload.
        3. Receive ACK segment with payload containing the file size to be sent during
        the connection.

        TODO clean up when allocating TCP state variables
        """
        logger.info(f"Waiting for SYN segment to establish connection...")
        self._listen_for_syn()

        logger.info(f"Sending SYNACK segment to client...")

        # The ACK will contain the file size
        payload = self._send_and_wait_for_ack(
            payload=b"", flags={"SYN", "ACK"}, expected_flags={"ACK"}
        )
        self.file_size = int.from_bytes(payload, byteorder="big")

        # Need to send ACK back to client. This is reliable because it is not sent over
        # the network.
        ack_segment = self.create_tcp_segment(
            payload=b"",
            seq_num=self.server_isn + 1,
            ack_num=self.client_isn + 1 + len(payload),
            flags={"ACK"},
        )
        self.socket.sendto(ack_segment, self.client_address)

        logger.info(
            f"================= Established connection with client! file_size: {self.file_size} ======================"
        )
        return

    def _send_and_wait_for_ack(self, payload, flags=set(), expected_flags=set()):
        """
        Keep sending TCP segments encapsulated in a UDP segment
        until we receive the ACK segment we are expecting.

        TODO: probably have to check ACK number too
        """
        # Create TCP segment. TODO: information on how the sequence number is incremented
        # and ack number is set.
        synack_segment = self.create_tcp_segment(
            payload=payload,
            seq_num=self.server_isn,
            ack_num=(self.client_isn + 1),
            flags=flags,
        )
        logger.info(f"Segment created with payload {payload} and flags {flags}")

        # Keep sending SYNACK segments for the maximum amount of retires
        # until we receive an ACK segment that is not corrupted and the one that we are expecting.
        # Keep track of the number of retries so we can differentiate between a successful
        # retransmission and reaching the maximum number of retries.
        retry_count = 0

        for _ in range(MAX_RETRIES + 1):
            retry_count += 1
            self.socket.sendto(synack_segment, self.client_address)

            try:
                segment, client_address = self.socket.recvfrom(2048)
                # Unpack the segment and extract the payload.
                seq_num, ack_num, flags, recv_window, payload = unpack_segment(segment)
                logger.info(
                    f"received segment with flags {flags}, ack number {ack_num}, seq number {seq_num}, and payload {payload}"
                )
                # Determine whether bits within the segment are corrupted. This
                # could occur due to noise in the links, malicious attackers, etc.
                # If the segment is corrupted, ignore it.
                if not verify_checksum(segment=segment):
                    logger.error("Checksum verification failed. Ignoring segment.")
                    continue
                logger.debug(f"Checksum verification passed for segment!")

                # Determine whether the flags in the segment are what we expect.
                # If not, ignore the segment.
                if not verify_flags(flags_byte=flags, expected_flags=expected_flags):
                    logger.error(f"Received segment with unexpected flags.")
                    continue
                logger.debug(f"Flag verification passed for segment!")

                break
            except timeout:
                logger.info(f"Timeout occurred while waiting for ACK. Retrying...")
                continue
            except Exception as e:
                logger.warning(f"Exception occurred while waiting for ACK: {e}")
                logger.warning(f"Traceback: {traceback.format_exc()}")
                continue

        if retry_count > MAX_RETRIES:
            logger.error(f"Maximum number of retries reached. Aborting...")
            sys.exit(1)

        return payload

    def _listen_for_syn(self):
        """
        Helper function for establishing a connection.

        Continuously listens for a SYN segment from the client and returns the client's
        randomly chosen ISN when a SYN segment is received.

        If the server does not receive a SYN segment, it will continue to listen,
        with timeouts reset accordingly.
        If the segment received does not have the SYN flag set, it is ignored.
        If the segment is corrupted (checksum verification fails), it is ignored.
        """
        # The client will send a SYN segment with no payload and a randomly chosen
        # sequence number. We need to receive this segment and stash the sequence
        # number so we can ack sequence + 1 when we send the SYNACK segment.
        # Keep track of the number of retries so we can differentiate between a successful
        # retransmission and reaching the maximum number of retries.
        retry_count = 0

        for _ in range(MAX_RETRIES + 1):
            retry_count += 1

            try:
                syn_segment, client_address = self.socket.recvfrom(40)

                seq_num, _, flags, recv_window, _ = unpack_segment(syn_segment)
                logger.info(
                    f"received segment with seq number {seq_num}, and flags {flags}"
                )

                # Determine whether bits within the segment are corrupted. This
                # could occur due to noise in the links, malicious attackers, etc.
                # If the segment is corrupted, ignore it.
                if not verify_checksum(segment=syn_segment):
                    logger.error("Checksum verification failed. Ignoring segment.")
                    continue
                logger.debug(f"Checksum verification passed for segment!")

                # Determine whether the flags in the segment are what we expect.
                # If not, ignore the segment.
                if not verify_flags(flags_byte=flags, expected_flags={"SYN"}):
                    logger.error(f"Received segment with SYN flag not set. Ignoring.")
                    continue
                logger.debug(f"Flag verification passed for segment!")

                self.client_isn = seq_num
                logger.info(f"SYN segment received with client ISN: {self.client_isn}")
                break
            except timeout:
                # TODO increase timeout acc. formula
                logger.info(
                    f"Timeout occurred while receiving SYN segment. Retrying..."
                )
                continue
            except Exception as e:
                logger.warning(f"Exception occurred while receiving SYN segment: {e}")
                logger.warning(f"Traceback: {traceback.format_exc()}")
                continue

        if retry_count > MAX_RETRIES:
            logger.error(f"Maximum number of retries reached. Aborting...")
            sys.exit(1)

        return self.client_isn

    def shutdown_server(self):
        pass

    def run(self):
        self.establish_connection()
        self.receive_file_gbn()
        return


def main():
    """ """
    parser = argparse.ArgumentParser(description="Bootleg TCP implementation over UDP")
    # TDOO: validate args
    parser.add_argument("file", type=str, help="file to send over TCP")
    parser.add_argument("listening_port", type=int, help="port to listen on")
    parser.add_argument("address_for_acks", type=str, help="address to send ACKs to")
    parser.add_argument("port_for_acks", type=int, help="port to send ACKs to")
    args = parser.parse_args()
    print("===============")
    print("TCPServer Parameters:")
    for arg in vars(args):
        print(f"{arg}: {getattr(args, arg)}")
    print("===============")

    if not validate_args(args, is_client=False):
        logger.error("Invalid arguments. Aborting...")
        sys.exit(1)

    tcp_server = SimplexTCPServer(
        args.file, args.listening_port, args.address_for_acks, args.port_for_acks
    )
    tcp_server.run()

    return


if __name__ == "__main__":
    main()
