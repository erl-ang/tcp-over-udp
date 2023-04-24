import argparse
from socket import *

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
        self.socket_num = 12345 # TODO change this later so there's no conflicts between port nums
    
    def create_and_bind_socket(self):
        """
        Create a UDP socket using IPv4
        """
        self.socket = socket(AF_INET, SOCK_DGRAM)
        self.socket.bind(('', self.ack_port_number))
        return self.socket
    
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
    print("===============")
    print("Printing args:")
    for arg in vars(args):
        print(arg, getattr(args, arg))
    print("===============")
    # TODO: validate args
    
    
    tcp_client = SimplexTCPClient(
        args.file, args.address_of_udpl,
        args.port_number_of_udpl, args.windowsize,
        args.ack_port_number
    )
    tcp_client.send_datagram()
    
    return

if __name__ == "__main__":
    main()
