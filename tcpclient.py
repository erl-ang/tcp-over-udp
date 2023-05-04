import argparse
from socket import *
from utils import (
    SimplexTCPHeader,
    verify_checksum,
    verify_flags,
    validate_args,
    unpack_segment,
)
import random
import logging
import struct
import sys
import os
import traceback

logger = logging.getLogger("TCPClient")
logger.setLevel(logging.INFO)

# To log on stdout, we create console handler with a higher log level, format it,
# and add the handler to logger.
ch = logging.StreamHandler()
ch.setLevel(logging.INFO)
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
ch.setFormatter(formatter)
logger.addHandler(ch)

# Implementations of TCP usually have a maximum number of retransmissions for a segment.
# 5-7 is a common valid.
MAX_RETRIES = 6

# Maximum segment size (MSS) is the maximum amount of data that can be carried in a single
# TCP segment. The MSS is specified during the initial connection setup.
MSS = 40


class SimplexTCPClient:
    """ """

    def __init__(
        self, file, address_of_udpl, port_number_of_udpl, windowsize, ack_port_number
    ):
        self.file = file
        self.proxy_address = (address_of_udpl, port_number_of_udpl)
        self.windowsize = windowsize
        self.ack_port_number = ack_port_number

        # Create a UDP socket using IPv4
        self.socket = self.create_and_bind_socket()
        logger.info(f"Socket created and bound to port {self.ack_port_number}")

        # Initialize TCP state variables
        self.client_isn = 0
        self.timeout = 0.5
        self.socket.settimeout(0.5)
        self.server_isn = 0

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
        3. Send ACK segment with payload.
        """
        logger.info(f"Establishing connection with server...")
        self._send_syn_and_wait_for_synack()

        # At this point, we have received a SYNACK segment from the server
        # send ack with the filesize
        logger.info(
            f"almost ESTABLISHED state: received SYNACK segment from server, still need to ACK"
        )
        return

    def send_file(self):
        """
        Uses the alternating bit protocol to send the file to the server.


        """

        # Send the specified file to the server in chunks of MSS bytes. Stop sending when
        # the server's receive window is full.
        file = open(self.file, "rb")
        file_size = os.path.getsize(self.file)

        # Keep track of last_byte_sent and last_byte_acked. To make sure that the client
        # is not overflowing the receive buffer of the server, the client makes sure that
        # the amount of unacked data <= rwnd. The amount of unacl data is last_byte_sent - last_byte_acked.
        last_byte_sent = 0
        last_byte_acked = 0

        while last_byte_acked < file_size:

            # # TODO: last_byte_sent - last_byte_acked = self.windowsize case?
            # while (
            #     last_byte_sent - last_byte_acked < self.windowsize
            #     and last_byte_sent < file_size
            # ):
            # TODO: pipelining
            payload = file.read(MSS)
            last_byte_sent += len(
                payload
            )  # explain why this is len(payload) and not MSS

            seq_num = self.client_isn + last_byte_sent
            ack_num = self.server_isn + last_byte_acked
            packet = self.create_tcp_segment(
                payload=payload, seq_num=seq_num, ack_num=ack_num, flags={"ACK"}
            )
            self.socket.sendto(packet, self.proxy_address)
            logger.info(
                f"Sent packet with sequence number {seq_num} and ack number {ack_num}"
            )

            try:
                ack, server_address = self.socket.recvfrom(MSS)
                # TODO: from_bytes method
                acked_byte = struct.unpack("!I", ack[8:12])[0]
                if acked_byte > last_byte_acked:
                    logger.info(f"Received ACK for byte {acked_byte}")
                    last_byte_acked = acked_byte
            except timeout:
                logger.info(f"TODO timeout")

            # TODO checksum verification, flag verification, etc.
            # Verify the ack num, discard OOO packets

            # retry_count = 0
            # for _ in range(MAX_RETRIES + 1):
            #     retry_count += 1

            #     self.socket.sendto(packet, self.proxy_address)
            #     logger.info(
            #         f"Sent packet with sequence number {seq_num} and ack number {ack_num}"
            #     )

            #     try:
            #         ack, server_address = self.socket.recvfrom(MSS)
            #         acked_byte = struct.unpack("!I", ack[8:12])[
            #             0
            #         ]  # TODO abstract this out

            #         # Ignoring OOO packets
            #         if acked_byte > last_byte_acked:
            #             last_byte_acked = acked_byte
            #     except timeout:

            #         continue
        # The windowsize is used to give the sender an idea of how much free buffer space
        # is available at the receiver. Both the sender and receiver maintain a variable
        # maintain a distinct receive window.

        return

    def _send_syn_and_wait_for_synack(self):
        """
        Send SYN segment with no payload, SYN flag set, and random sequence number.
        Generate random sequence number, which will be the client's ISN that will be incremented
        for each segment sent.
        """
        self.client_isn = random.randint(0, 2**32 - 1)
        logger.info(f"Client ISN: {self.client_isn}")

        # Create SYN segment with no payload, SYN flag set, and random sequence number. We
        # set the ack number to 0 because we are not acknowledging any data from the server.
        syn_segment = self.create_tcp_segment(
            payload=b"", seq_num=self.client_isn, ack_num=0, flags={"SYN"}
        )

        # Keep track of the number of retries so we can differentiate between a successful
        # retransmission and reaching the maximum number of retries.
        retry_count = 0

        for _ in range(MAX_RETRIES + 1):
            retry_count += 1
            self.socket.sendto(syn_segment, self.proxy_address)
            logger.info(f"Entered SYN_SENT state: sent SYN segment to server")

            try:
                # TODO: change buffer size

                synack_segment, server_address = self.socket.recvfrom(2048)

                seq_num, ack_num, flags, recv_window, _ = unpack_segment(synack_segment)

                if not verify_checksum(
                    synack_segment
                ):  # TODO: make sure logging level sare consistent
                    logger.error(f"Checksum verification failed for SYNACK segment")
                    continue
                logger.info(f"Checksum verification passed for segment! SYNACK")

                if not verify_flags(flags_byte=flags, expected_flags={"SYN", "ACK"}):
                    logger.error(f"SYNACK segment does not have SYN and ACK flag set")
                    continue
                logger.info(f"Flag verification passed for segment!")

                # Check if the ACK number is correct.
                # ack_num = struct.unpack("!I", synack_segment[8:12])[0]
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

        if retry_count > MAX_RETRIES:
            logger.error(f"Maximum number of retries reached. Aborting...")
            sys.exit(1)

        return self.server_isn

    def create_tcp_segment(self, payload, seq_num, ack_num, flags):
        """
        Creates a TCP segment with the given payload and flags.

        :param payload: payload to be sent to the server
        :param flags: set of flags to be set in the TCP header
        """
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
        tcp_segment = tcp_header + payload

        return tcp_segment

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
