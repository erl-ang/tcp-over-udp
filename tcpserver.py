import argparse
from socket import *
from utils import SimplexTCPHeader, calculate_checksum, verify_checksum, verify_flags
import logging
import struct
import traceback
import random

logger = logging.getLogger("TCPServer")
logger.setLevel(logging.INFO)

# create console handler with a higher log level
ch = logging.StreamHandler()
ch.setLevel(logging.INFO)

# create formatter and add it to the handler
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
ch.setFormatter(formatter)

# add the handler to the logger
logger.addHandler(ch)


def validate_args():
    """ """
    pass


class SimplexTCPServer:
    """ """

    def __init__(self, file, listening_port, address_for_acks, port_for_acks):
        self.file = file
        self.listening_port = listening_port
        self.client_address = (address_for_acks, port_for_acks)

        self.socket = self.create_and_bind_socket()
        self.socket.settimeout(0.5)
        logger.info(f"Socket created and bound to port {self.listening_port}")

        self.cur_ack_num = -1
        self.seq_num = random.randint(0, 2**32 - 1)
        return

    def create_and_bind_socket(self):
        """
        Creates a UDP socket and binds it to the listening port.
        """
        self.socket = socket(AF_INET, SOCK_DGRAM)
        self.socket.bind(("", self.listening_port))
        return self.socket

    def create_tcp_segment(self, payload, flags):
        """
        Creates a TCP segment with the given payload and flags.

        :param payload: payload to be sent to the server
        :param flags: set of flags to be set in the TCP header
        """
        # Create the segment without the checksum. Increment the ack number,
        # indicating that the server has received up to (not including) the cur_ack_num sequence number.
        self.cur_ack_num += 1
        logger.info(f"Sending segment with ack number {self.cur_ack_num}")

        tcp_segment = SimplexTCPHeader(
            src_port=self.listening_port,
            dest_port=self.client_address[1],
            seq_num=self.seq_num,  # TODO increment
            ack_num=self.cur_ack_num,
            recv_window=10,  # TODO: change this
            flags=flags,
        )

        # Attach the TCP header to payload.
        tcp_header = tcp_segment.make_tcp_header(payload)
        tcp_segment = tcp_header + payload

        return tcp_segment

    def establish_connection(self):
        """
        Establishes a connection with the client address.
        1. Receive SYN segment with random sequence number and no payload.
        2. Send SYNACK segment to client with random sequence number, SYN and ACK fields, and no payload.
        3. Receive ACK segment with payload.
        """
        logger.info(f"Waiting for SYN segment to establish connection...")
        self.cur_ack_num = self._listen_for_syn()

        logger.info(f"Sending SYNACK segment to client...")
        self._send_and_wait_for_ack(
            payload=b"", flags={"SYN", "ACK"}, expected_flags={"ACK"}
        )
        return

    def _send_and_wait_for_ack(self, payload, flags=None, expected_flags=None):
        """
        Keep sending TCP segments encapsulated in a UDP segment
        until we receive the ACK segment we are expecting.

        TODO: probably have to check ACK number too
        """
        # Create TCP segment. TODO: information on how the sequence number is incremented
        # and ack number is set.
        synack_segment = self.create_tcp_segment(payload=payload, flags=flags)
        logger.info(f"Segment created with payload {payload} and flags {flags}")

        # Keep sending SYNACK segments until we receive an ACK segment that is
        # not corrupted and the one that we are expecting.
        while True:
            self.socket.sendto(synack_segment, self.client_address)
            logger.info(f"Segment sent!")

            try:
                message, client_address = self.socket.recvfrom(2048)

                # Determine whether bits within the segment are corrupted. This
                # could occur due to noise in the links, malicious attackers, etc.
                # If the segment is corrupted, ignore it.
                if not verify_checksum(segment=message):
                    logger.error("Checksum verification failed. Ignoring segment.")
                    continue
                logger.info(f"Checksum verification passed for segment!")

                # Determine whether the flags in the segment are what we expect.
                # If not, ignore the segment.
                logger.info(f"flags_byte: {message[13]}")
                if not verify_flags(
                    flags_byte=message[13], expected_flags=expected_flags
                ):
                    logger.error(f"Received segment with unexpected flags.")
                    continue
                logger.info(f"Flag verification passed for segment!")

                break
            except timeout:
                logger.info(f"Timeout occurred while waiting for ACK. Retrying...")
                continue
            except Exception as e:
                logger.warning(f"Exception occurred while waiting for ACK: {e}")
                logger.warning(f"Traceback: {traceback.format_exc()}")
                continue

        return

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
        client_isn = None

        while True:
            try:
                syn_segment, client_address = self.socket.recvfrom(2048)

                # Determine whether bits within the segment are corrupted. This
                # could occur due to noise in the links, malicious attackers, etc.
                # If the segment is corrupted, ignore it.
                if not verify_checksum(segment=syn_segment):
                    logger.error("Checksum verification failed. Ignoring segment.")
                    continue
                logger.info(f"Checksum verification passed for segment!")

                # Determine whether the flags in the segment are what we expect.
                # If not, ignore the segment.
                if not verify_flags(flags_byte=syn_segment[13], expected_flags={"SYN"}):
                    logger.error(
                        f"Received segment with SYN flag not set. Ignoring. Message: {syn_segment.decode()}"
                    )
                    continue
                logger.info(f"Flag verification passed for segment!")

                # We need to unpack the sequence number byte string from the segment in a format that we can use
                client_isn = struct.unpack("!I", syn_segment[4:8])[0]

                logger.info(f"Checksum verification passed for SYN segment")
                logger.info(f"SYN segment received with client ISN: {client_isn}")
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

        return client_isn

    def shutdown_server(self):
        pass


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
    # validate_args(args, parser)

    tcp_server = SimplexTCPServer(
        args.file, args.listening_port, args.address_for_acks, args.port_for_acks
    )

    tcp_server.establish_connection()
    return


if __name__ == "__main__":
    main()
