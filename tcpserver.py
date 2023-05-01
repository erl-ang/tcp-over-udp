import argparse
from socket import *
import utils
import logging
import struct

logger = logging.getLogger("TCPServer")
logger.setLevel(logging.INFO)

# create console handler with a higher log level
ch = logging.StreamHandler()
ch.setLevel(logging.INFO)

# create formatter and add it to the handler
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)

# add the handler to the logger
logger.addHandler(ch)

def validate_args():
    """
    """
    pass

class SimplexTCPServer:
    """
    
    """
    def __init__(self, file, listening_port, address_for_acks, port_for_acks):
        self.file = file
        self.listening_port = listening_port
        self.client_address = (address_for_acks, port_for_acks)
        
        self.socket = self.create_and_bind_socket()
        logger.info(f"Socket created and bound to port {self.listening_port}")
        return
        
    def create_and_bind_socket(self):
        """
        Creates a UDP socket and binds it to the listening port.
        """
        self.socket = socket(AF_INET, SOCK_DGRAM)   
        self.socket.bind(('', self.listening_port))
        return self.socket
    
    def establish_connection(self):
        """
        Establishes a connection with the client address.
        1. Receive SYN segment with random sequence number and no payload.
        2. Send SYNACK segment to client with random sequence number, SYN and ACK fields, and no payload.
        3. Send ACK segment with payload.
        """
        # TODO what if does not receive SYN segment
        while True:
            try:
                syn_segment, client_address = self.socket.recvfrom(2048)
                # TODO abstraction for this with header later.
                if syn_segment[13] & 0b00000010:
                    # We need to unpack the sequence number byte string from the segment in a format that we can use
                    #
                    client_isn = struct.unpack("!I", syn_segment[4:8])[0]
                    logger.info(f"SYN segment received from {client_address} with client ISN: {client_isn}")
                    break
                else:
                    logger.warning(f"Received segment with SYN flag not set. Ignoring. Message: {syn_segment.decode()}")
                    continue
            except timeout:
                # TODO increase timeout acc. formula
                continue
            except Exception as e:
                logger.warning(f"Exception occurred while receiving SYN segment: {e}")
        return
        
        
    
    def create_datagram(self):
        pass
    
    def send_datagram(self):
        pass
    
    def read_datagram(self):
        message, proxy_address = self.socket.recvfrom(2048)
        print(f"proxy's address: {proxy_address}")
        
        # TODO remove later
        modified_message = message.decode().upper()
        self.socket.sendto(modified_message.encode(), self.client_address)
        print("here")
        self.socket.close()
        return
    
    
    def shutdown_server(self):
        pass
    
    
def main():
    """
    """
    parser = argparse.ArgumentParser(
        description="Bootleg TCP implementation over UDP"
    )
    # TDOO: validate args
    parser.add_argument(
        "file", type=str,
        help="file to send over TCP"
    )
    parser.add_argument(
        "listening_port", type=int,
        help="port to listen on"
    )
    parser.add_argument(
        "address_for_acks", type=str,
        help="address to send ACKs to"
    )
    parser.add_argument(
        "port_for_acks", type=int,
        help="port to send ACKs to"
    )
    args = parser.parse_args()
    print("===============")
    print("TCPServer Parameters:")
    for arg in vars(args):
        print(f"{arg}: {getattr(args, arg)}")
    print("===============")
    # validate_args(args, parser)
    
    tcp_server = SimplexTCPServer(
        args.file, args.listening_port,
        args.address_for_acks, args.port_for_acks
    )
    
    tcp_server.establish_connection()
    return

if __name__ == "__main__":
    main()
