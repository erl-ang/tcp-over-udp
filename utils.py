import logging
from typing import Set
import sys
import ipaddress
import os
import struct

logger = logging.getLogger("UTILS    ")
logger.setLevel(logging.INFO)

# To log on stdout, we create console handler with a higher log level, format it,
# and add the handler to logger.
ch = logging.StreamHandler()
ch.setLevel(logging.INFO)
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
ch.setFormatter(formatter)
logger.addHandler(ch)

# Bit masks for the flags field in the TCP header
# used to set and check the flags of segments transmitted.
ACK_MASK = 0b00010000
RST_MASK = 0b00001000
SYN_MASK = 0b00000100
FIN_MASK = 0b00000010

# Maximum segment size (MSS) is the maximum amount of data that can be carried in a single
# TCP segment. The MSS is specified during the initial connection setup.
MSS = 40

# Implementations of TCP usually have a maximum number of retransmissions for a segment.
# 5-7 is a common valid.
MAX_RETRIES = 6
INITIAL_TIMEOUT = 0.5

class SimplexTCPHeader:
    """
    Formats a TCP header
    """

    def __init__(
        self,
        src_port: int,
        dest_port: int,
        seq_num: int,
        ack_num: int,
        recv_window: int,
        flags: Set[str],
    ):
        """
        Initializes a TCP header with the specified fields:

        :params:
        - src_port: Source port number
        - dest_port: Destination port number
        - seq_num: Sequence number
        - ack_num: Acknowledgement number
        - recv_window: Receive window
        - flags: Flags, a set of strings. Possible values are "ACK", "RST", "SYN", and "FIN".
        """
        # Source and destination port numbers are used for multiplexing
        # and demultiplexing.
        self.src_port = src_port
        self.dest_port = dest_port

        # The sequence number and acknowledgemnt number fields are used
        # to implement reliability in the TCP protocol.
        self.seq_num = seq_num
        self.ack_num = ack_num

        # The header length field specifies the length of the TCP header.
        # For our purposes, the header length is always 20 bytes because
        # the TCP options field is not used.
        self.header_len_bytes = 20

        # We only use the ACK, RST, SYN, and FIN flags, which are used
        # for connection setup and teardown. The other bits are not used
        # as they are used for ECN and indicating the presence of urgent
        # data.
        for flag in flags:
            if flag not in {"ACK", "RST", "SYN", "FIN"}:
                # TODO: test this
                logger.warning(f"Invalid flag {flag} specified. Removing from flags.")
                flags.remove(flag)
        self.flags = flags

        # The receive window field specifies the number of bytes that the
        # receiver is willing to accept. It is used for flow control.
        self.recv_window = recv_window

        # The checksum field is used to detect errors in the TCP header.
        self.checksum = None

        return

    def make_tcp_header(self, payload: bytes):
        """
        Returns a bytearray representing the TCP header with the checksum.

        Note that the checksum is computed over the entire segment, including
        the TCP header (with the checksum field set to 0) and the payload.
        """
        # TODO: change naming to tcp_header
        tcp_segment = self._make_tcp_header_without_checksum()
        tcp_segment.extend(payload)
        tcp_segment[16:18] = calculate_checksum(tcp_segment)
        logger.debug(
            f"Putting checksum in header: {int.from_bytes(tcp_segment[16:18], byteorder='big')}"
        )

        return tcp_segment

    def _make_tcp_header_without_checksum(self):
        """
        Returns a bytearray representing the TCP header without the checksum
        with the beader fields set to the values specified in the constructor.

        The format and field lengths of the 20-byte TCP header follow the TCP segment
        structure in K&R pg 231:
        ==============================================================================
        |     Source port number (2 bytes)        | Destination port number (2 bytes)|
        |============================================================================|
        | Sequence number (4 bytes)                                                  |
        |============================================================================|
        | Acknowledgement number (4 bytes)                                           |
        |============================================================================|
        | Header len (4 bits)|Unused|Flags(8 bits)| Receive window (2 bytes)         |
        |============================================================================|
        | Checksum (2 bytes)                      | Unused                           |
        |============================================================================|
        """
        tcp_header = bytearray(20)

        # Source and destination port numbers are 16 bits long.
        tcp_header[0:2] = self.src_port.to_bytes(2, byteorder="big")
        tcp_header[2:4] = self.dest_port.to_bytes(2, byteorder="big")

        # The sequence number and acknowledgement number fields are 32 bits long.
        tcp_header[4:8] = self.seq_num.to_bytes(4, byteorder="big")
        tcp_header[8:12] = self.ack_num.to_bytes(4, byteorder="big")

        # The header length field is 4 bits and specifies the length of the TCP
        # header. Note that the header length field is the number of 32-bit words in the
        # header, so we divide by 4.
        tcp_header[12] = (self.header_len_bytes // 4) << 4

        # The remaining 4 bits in the byte containing the header length are unused.

        # The flag field is 8 bits long. We only use the ACK, RST, SYN, and FIN bits.
        flags_byte = 0b00000000
        if "ACK" in self.flags:
            flags_byte |= ACK_MASK
        if "RST" in self.flags:
            flags_byte |= RST_MASK
        if "SYN" in self.flags:
            flags_byte |= SYN_MASK
        if "FIN" in self.flags:
            flags_byte |= FIN_MASK

        tcp_header[13] = flags_byte

        # The receive window is 16 bits long.
        tcp_header[14:16] = self.recv_window.to_bytes(2, byteorder="big")

        # The checksum field is 16 bits long and set to 0 for the purposes of
        # calculating the checksum.
        tcp_header[16:18] = 0x0000.to_bytes(2, byteorder="big")

        # The urgent pointer field is 16 bits long. It is used to indicate the end of
        # urgent data. This is not used in our implementation, so we set it to 0.
        tcp_header[18:20] = 0x0000.to_bytes(2, byteorder="big")

        return tcp_header


def unpack_segment(segment):
    """
    Break the TCP segment into its constituent fields.

    Only extracts the fields necessary for this application,
    which are the sequence number, acknowledgement number,
    flags, recv_window, and payload. The checksum is not
    unpacked from the rest of the segment as it must be computed
    over the entire segment anyway.

    :param segment: The TCP segment to unpack.
    """
    # TODO: make the extraction of fields consistent, can specify a format
    # string for the struct.unpack function.

    # Extract the fields from the TCP header.
    header = segment[:20]
    seq_num = struct.unpack("!I", header[4:8])[0]
    ack_num = struct.unpack("!I", header[8:12])[0]
    flags = header[13]
    recv_window = int.from_bytes(header[14:16], byteorder="big")

    payload = segment[20:]
    return seq_num, ack_num, flags, recv_window, payload


def validate_args(args, is_client=False):
    """
    Validates command line arguments for the TCP client and server.

    Checks that the IP addresses are valid, port numbers are within the
    valid range, and if the file to be sent exists.

    :param arg: The command line arguments.
    :param client: Whether the arguments are for the client or server.
    """
    # For both the client and server, validate whether the file exists
    # in the file system.
    file_path = args.file

    if not os.path.exists(file_path):
        logger.error("File does not exist.")
        return False

    # Group the port numbers and IP addresses together for validation.
    port_nums = []
    ip_addresses = []
    if is_client:
        port_nums.append(args.port_number_of_udpl)
        port_nums.append(args.ack_port_number)
        ip_addresses.append(args.address_of_udpl)
    else:
        port_nums.append(args.listening_port)
        port_nums.append(args.port_for_acks)
        ip_addresses.append(args.address_for_acks)

    # IP addresses should be valid IPv4 or IPv6 addresses in dotted decimal
    # notation. Note that even though localhost is a valid IP address, the ipaddress
    # module will not recognize it.
    for address in ip_addresses:
        try:
            ipaddress.ip_address(address)
        except ValueError:
            logger.error(
                f"Invalid IP address {address}. Make sure the IP address is valid and in dotted decimal notation."
            )
            return False

    # Port number should be an integer value in the range 1024-65535.
    for port_num in port_nums:
        if port_num < 1024 or port_num > 65535:
            logger.error(
                f"Invalid port number {port_num}. Port number should be an integer value in the range 1024-65535"
            )
            return False

    # Window size should be a multiple of MSS.
    if is_client:
        if args.windowsize % MSS != 0:
            logger.error(
                f"Invalid window size {args.windowsize}. Window size should be a multiple of 40 bytes, the MSS"
            )
            return False
    return True


def calculate_checksum(segment: bytearray):
    """
    Used to determine whether bits within a segment have been altered as the
    segment moved from source to destination. When a TCP sender creates a segment,
    the TCP sender will calculate the checksum and place it in the checksum field
    in the header.

    The checksum is calculated by taking the 1s complement of the sum of all the 16-bit
    words in the segment (header AND data with checksum set to 0), with any
    overflow encountered during the sum being wrapped around.

    1s complement is obtained by flipping all the bits in a number.
    """
    # Ensure segment's length is a multiple of 2 bytes by padding a 0 byte onto a copy.
    segment_copy = bytearray(segment)
    if len(segment) % 2 == 1:
        logging.info(f"Segment length is {len(segment)} bytes, padding with 0 byte.")
        segment_copy.extend(b"\x00")

    # Calculate the sum of all the 16-bit words in the segment. We
    # iterate over every other byte because a 16-bit word is 2 bytes.
    checksum = 0
    for i in range(0, len(segment_copy), 2):

        # Convert the 2 bytes into a 16-bit word so we can add it to the sum.
        word = (segment_copy[i] << 8) + segment_copy[i + 1]
        checksum += word

        # Wrap around if overflow occurs. To implement this, we need to zero
        # out the overflow bit and add 1 to the sum.
        if checksum > 0xFFFF:
            checksum = (checksum & 0xFFFF) + 1

    # Take the 1s complement of the sum and truncate to 16 bits.
    checksum = ~checksum & 0xFFFF

    return checksum.to_bytes(2, byteorder="big")


def verify_checksum(segment):
    """
    Verify the checksum of a segment to make sure no errors have been introduced.
    """
    segment_checksum = int.from_bytes(segment[16:18], byteorder="big")
    logger.debug(f"segment's checksum: {segment_checksum}")

    # Set the checksum field to 0 so that the redone checksum calculation is aligns
    # with the original checksum calculation.
    segment = segment[:16] + b"\x00\x00" + segment[18:]

    calculated_checksum = int.from_bytes(calculate_checksum(segment), byteorder="big")
    logger.debug(f"calculated checksum: {calculated_checksum}")
    # The following commented out section is deprecated:
    # calculated_checksum = ~calculated_checksum & 0xFFFF

    # # Check if the calculated checksum matches the checksum in the segment.
    # # The checksum is valid if checksum + calculated checksum = 1111111111111111.
    # calculated_checksum += segment_checksum
    # if calculated_checksum > 0xFFFF:
    #     calculated_checksum = (calculated_checksum & 0xFFFF) + 1
    # calculated_checksum == 0xFFFF

    return calculated_checksum == segment_checksum


def verify_flags(flags_byte, expected_flags=None):
    """
    Verify that the flags received match the expected flags by
    parsing the 8-bit flags field in the TCP header.
    """
    # TODO: flags_bits is passed as an int, but it is actually a byte. This
    #      should be fixed.
    logger.debug(
        f"Checking if flags {expected_flags} match flags set in the received segment's header"
    )

    # If no expected flags are specified, then we assume that the flags are
    # correct.
    if not expected_flags:
        return True

    # Otherwise, we check that the flags are correct by checking if the
    # flag bit is set in the TCP header for each expected flag.
    if "ACK" in expected_flags:
        if not flags_byte & ACK_MASK:
            logger.error("Expected ACK but received message with ACK flag not set.")
            return False
    if "RST" in expected_flags:
        if not flags_byte & RST_MASK:
            logger.error("Expected RST but received message with RST flag not set.")
            return False
    if "SYN" in expected_flags:
        if not flags_byte & SYN_MASK:
            logger.error("Expected SYN but received message with SYN flag not set.")
            return False
    if "FIN" in expected_flags:
        if not flags_byte & FIN_MASK:
            logger.error("Expected FIN but received message with FIN flag not set.")
            return False
    return True
