import argparse
from socket import *
import utils
import random
import logging

logger = logging.getLogger("TCPClient")
logger.setLevel(logging.INFO)

# create console handler with a higher log level
ch = logging.StreamHandler()
ch.setLevel(logging.INFO)

# create formatter and add it to the handler
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)

# add the handler to the logger
logger.addHandler(ch)

class SimplexTCPClient:
    """
    
    """
    def __init__(self, file, address_of_udpl, port_number_of_udpl, windowsize, ack_port_number):
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
        self.socket.bind(('', self.ack_port_number))
        return self.socket
    
    def establish_connection(self):
        """
        Establishes a connection with the destination address.
        1. Send SYN segment with random sequence number and no payload.
        2. Receive SYNACK segment from server.
        3. Send ACK segment with payload.
        """
        # 1. Send SYN segment with no payload, SYN flag set, and random sequence number.
        # Generate random sequence number, which will be the client's ISN that will be incremented
        # for each segment sent.
        self.client_isn = random.randint(0, 2**32 - 1)
        logger.info(f"Client ISN: {self.client_isn}")
        
        # Create the SYN segment without the checksum.
        syn_segment = utils.make_tcp_header_without_checksum(
            src_port=self.ack_port_number,
            dest_port=self.proxy_address[1],
            seq_num=self.client_isn,
            ack_num=0,
            recv_window=self.windowsize,
            flags=["SYN"]
        )
        logger.info(f"SYN segment created, type: {type(syn_segment)}")
        
        # Attach checksum to the segment.
        # TODO refactor this out. Will test checksum later
        # checksum = utils.calculate_checksum(syn_segment)
        # syn_segment[16:18] = checksum
        
        while True:
            self.socket.sendto(syn_segment, self.proxy_address)
            try:
                # TODO: change buffer size
                synack_segment, server_address = self.socket.recvfrom(2048)
                break   
            except timeout:
                # TODO: increase timeout acc. to formula in book.
                continue
            except Exception as e:
                logger.warning(f"Exception occurred while receiving SYNACK segment: {e}")
                continue
        
        
                
        
        
        
        return
        
        
    
    def get_data(self):
        """
        For now, data will be a string literal. Later have to read file contents
        to send to the server.
        """
        return input('Input message here: ')
        
    
    def read_datagram(self):
        """
        """
        message, server_address = self.socket.recvfrom(2048)
        print(f"message received: {message.decode()}")
        return
    
    def send_datagram(self):
        """
        Forwards the data to the link emulator.
        """
        message = self.get_data()
        
        # Attach destination address to the message.
        self.socket.sendto(message.encode(), self.proxy_address)
        modified_message, server_address = self.socket.recvfrom(2048)
        print(modified_message.decode())
        self.socket.close()
        return
    
    def shutdown_client(self):
        """
        """
        self.socket.close()
        return


def main():
    """
    """
    parser = argparse.ArgumentParser(
        description="Bootleg TCP implementation over UDP"
    )
    # TDOO: validate args
    parser.add_argument(
        "file", type=str,
        help="file that client reads data from"
    )
    parser.add_argument(
        "address_of_udpl", type=str,
        help="emulator's address"
    )
    parser.add_argument(
        "port_number_of_udpl", type=int,
          help="emulator's port number"
    )
    parser.add_argument(
        "windowsize", type=int,
        help="window size in bytes"
    )
    parser.add_argument(
        "ack_port_number", type=int,
        help="port number for ACKs"
    )
    args = parser.parse_args()
    print("=============================")
    print("TCPClient Parameters:")
    for arg in vars(args):
        print(f"{arg}: {getattr(args, arg)}")
    print("==============================")
    # TODO: validate args
    
    
    tcp_client = SimplexTCPClient(
        args.file, args.address_of_udpl,
        args.port_number_of_udpl, args.windowsize,
        args.ack_port_number
    )
    tcp_client.establish_connection()
    
    return

if __name__ == "__main__":
    main()
