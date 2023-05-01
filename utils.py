HEADER_LEN = 20
import logging

def make_tcp_header(
    src_port, dest_port, seq_num, ack_num, recv_window, flags
):
    # TODO test
    tcp_header = make_tcp_header_without_checksum(
        src_port, dest_port, seq_num, ack_num, recv_window, flags
    )
    tcp_header[16:18] = calculate_checksum(tcp_header)
    return tcp_header

def make_tcp_header_without_checksum(
    src_port, dest_port, seq_num, ack_num, recv_window, flags
):
    """
    The TCP header is 20 bytes long. It contains the following fields:
    - Source port number (2 bytes)
    - Destination port number (2 bytes)
    - Sequence number (4 bytes)
    - Acknowledgement number (4 bytes)
    - Receive window (2 bytes)
    - Header length (4 bits)
    - Flags (8 bits)
    - Checksum (2 bytes, computed after the header is created)
    - Urgent pointer (2 bytes, not used)
    """
    tcp_header = bytearray(20)

    # Source and destination port numbers are 16 bits long. These are used
    # for multiplexing and demultiplexing. We use the big endian byte order
    # for all fields.
    tcp_header[0:2] = src_port.to_bytes(2, byteorder="big")
    tcp_header[2:4] = dest_port.to_bytes(2, byteorder="big")

    # The sequence number and acknowledgement number fields are 32 bits long.
    # These are used to implement reliability in the TCP protocol.
    tcp_header[4:8] = seq_num.to_bytes(4, byteorder="big")
    tcp_header[8:12] = ack_num.to_bytes(4, byteorder="big")

    # The header length field is 4 bits and specifies the length of the TCP
    # header. For our purposes, the header length is always 20 bytes because
    # the TCP options field is not used.
    # Note that the header length field is the number of 32-bit words in the
    # header, so we divide by 4.
    tcp_header[12] = (HEADER_LEN // 4) << 4

    # The remaining 4 bits in the byte containing the header length are unused.

    # The flag field is 8 bits long. We only use the ACK, RST, SYN, and FIN bits,
    # which are used for connection setup and teardown. The other bits are not
    # used as they are used for ECN and indicating the presence of urgent data.
    flags_byte = 0b00000000
    if "ACK" in flags:
        flags_byte |= 0b00010000
    if "RST" in flags:
        flags_byte |= 0b00000100
    if "SYN" in flags:
        flags_byte |= 0b00000010
    if "FIN" in flags:
        flags_byte |= 0b00000001

    tcp_header[13] = flags_byte

    # The receive window is 16 bits long. It is used for flow control,
    # indicating how many bytes the receiveer is willing to accept.
    tcp_header[14:16] = recv_window.to_bytes(2, byteorder="big")

    # The checksum field is 16 bits long. It is used to detect whether errors have
    # been introduced into the segment.
    # tcp_header[16:18] = checksum.to_bytes(2, byteorder="big")

    # The urgent pointer field is 16 bits long. It is used to indicate the end of
    # urgent data. This is not used in our implementation.

    return tcp_header


def calculate_checksum(segment):
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
    # Ensure segment's length is a multiple of 2 bytes by padding a 0 byte.
    if len(segment) % 2 != 0:
        logging.info(f"Segment length is {len(segment)} bytes, padding with 0 byte.")
        segment += b"\x00"

    # Calculate the sum of all the 16-bit words in the segment. We
    # iterate over every other byte because a 16-bit word is 2 bytes.
    checksum = 0
    for i in range(0, len(segment), 2):

        # Convert the 2 bytes into a 16-bit word so we can add it to the sum.
        word = segment[i] << 8 + segment[i + 1]
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

    If no errors are introduced into the packet, then the sum at the receiver
    will be 1111111111111111.
    """
    segment_checksum = int.from_bytes(segment[16:18], byteorder="big")
    
    # Set the checksum field to 0 so that the redone checksum calculation is aligns
    # with the original checksum calculation.
    segment[16:18] = b"\x00\x00"

    calculated_checksum = calculate_checksum(segment)

    # Check if the calculated checksum matches the checksum in the segment.
    # The checksum is valid if checksum + calculated checksum = 1111111111111111.
    calculated_checksum += segment_checksum
    if calculated_checksum > 0xFFFF:
        calculated_checksum = (calculated_checksum & 0xFFFF) + 1

    return calculated_checksum == 0xFFFF
