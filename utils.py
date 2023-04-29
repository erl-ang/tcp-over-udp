from typing import Set
HEADER_LENGTH = 20
DEBUG = True

def make_tcp_header(source_port, destination_port, sequence_number, ack_number, receive_window, flags, checksum):
    """
    The TCP header is 20 bytes long. It contains the following fields:
    - Source port number (2 bytes)
    - Destination port number (2 bytes)
    - Sequence number (4 bytes)
    - Acknowledgement number (4 bytes)
    - Receive window (2 bytes)
    - Header length (4 bits)
    - Flags (8 bits)
    - Checksum (2 bytes)
    - Urgent pointer (2 bytes, not used)
    """
    tcp_header = bytearray(20)
    
    # Source and destination port numbers are 16 bits long. These are used 
    # for multiplexing and demultiplexing. We use the big endian byte order 
    # for all fields.
    tcp_header[0:2] = source_port.to_bytes(2, byteorder="big")
    tcp_header[2:4] = destination_port.to_bytes(2, byteorder="big")
    
    # The sequence number and acknowledgement number fields are 32 bits long.
    # These are used to implement reliability in the TCP protocol.
    tcp_header[4:8] = sequence_number.to_bytes(4, byteorder="big")
    tcp_header[8:12] = ack_number.to_bytes(4, byteorder="big")
    
    
    # The header length field is 4 bits and specifies the length of the TCP
    # header. For our purposes, the header length is always 20 bytes because
    # the TCP options field is not used.
    # Note that the header length field is the number of 32-bit words in the
    # header, so we divide by 4.
    tcp_header[12] = (HEADER_LENGTH // 4) << 4
    
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
    tcp_header[14:16] = receive_window.to_bytes(2, byteorder="big")
    
    
    # The checksum field is 16 bits long. It is used to detect whether errors have
    # been introduced into the segment.
    tcp_header[16:18] = checksum.to_bytes(2, byteorder="big")
    
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
    words in the segment (header AND data), with any overflow encountered during the sum
    being wrapped around.
    
    1s complement is obtained by flipping all the bits in a number.
    """
    pass

def verify_checksum(segment, checksum):
    """
    
    """
    pass