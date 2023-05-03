import argparse
from socket import *
from utils import SimplexTCPHeader, verify_checksum, verify_flags, validate_args
import random
import logging
import struct
import sys

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
        logger.info(
            f"Entered ESTABLISHED state: received SYNACK segment from server and sent ACK"
        )
        pass

    def send_file():
        """ """
        # Read data from the specified file
        # send it to the emulator's address and port
        # receive acks on teh ack_port_number

        pass

    def _send_syn_and_wait_for_synack(self):
        """
        Send SYN segment with no payload, SYN flag set, and random sequence number.
        Generate random sequence number, which will be the client's ISN that will be incremented
        for each segment sent.
        """
        self.client_isn = random.randint(0, 2**32 - 1)
        logger.info(f"Client ISN: {self.client_isn}")

        # Create SYN segment with no payload and SYN flag set.
        syn_segment = self.create_tcp_segment(payload=b"", flags={"SYN"})

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
                if not verify_checksum(
                    synack_segment
                ):  # TODO: make sure logging level sare consistent
                    logger.error(f"Checksum verification failed for SYNACK segment")
                    continue
                logger.info(f"Checksum verification passed for segment! SYNACK")

                if not verify_flags(
                    flags_byte=synack_segment[13], expected_flags={"SYN", "ACK"}
                ):
                    logger.error(f"SYNACK segment does not have SYN and ACK flag set")
                    continue
                logger.info(f"Flag verification passed for segment!")

                # Check if the ACK number is correct.
                ack_num = struct.unpack("!I", synack_segment[4:8])[0]
                if ack_num != self.client_isn + 1:
                    logger.error(
                        f"ACK number is incorrect, expected {self.client_isn + 1}, received: {ack_num}"
                    )
                    continue

                # Stash the server's ISN for future use. This will be used to ACK the server's segments.
                self.server_isn = struct.unpack("!I", synack_segment[8:12])[0]
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
                continue

        if retry_count > MAX_RETRIES:
            logger.error(f"Maximum number of retries reached. Aborting...")
            sys.exit(1)

        return self.server_isn

    def create_tcp_segment(self, payload, flags):
        """
        Creates a TCP segment with the given payload and flags.

        :param payload: payload to be sent to the server
        :param flags: set of flags to be set in the TCP header
        """

        # Create the segment without the checksum.
        tcp_segment = SimplexTCPHeader(
            src_port=self.ack_port_number,
            dest_port=self.proxy_address[1],
            seq_num=self.client_isn,  # TODO increment
            ack_num=0,  # TODO increment this
            recv_window=self.windowsize,
            flags=flags,
        )

        # Attach the TCP header to payload.
        tcp_header = tcp_segment.make_tcp_header(payload)
        tcp_segment = tcp_header + payload

        return tcp_segment

    def shutdown_client(self):
        """ """
        self.socket.close()
        return

    def run(self):
        self.establish_connection()
        return


def main():
    """ """
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

    if not validate_args(args, is_client=True):
        logger.error("Invalid arguments. Aborting...")
        sys.exit(1)

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
