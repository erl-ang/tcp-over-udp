import argparse
from socket import *

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
        self.address_for_acks = address_for_acks
        self.port_for_acks = port_for_acks
        
        self.socket = self.create_and_bind_socket()
        
        return
        
    def create_and_bind_socket(self):
        """
        Creates a UDP socket and binds it to the listening port.
        """
        self.socket = socket(AF_INET, SOCK_DGRAM)   
        self.socket.bind(('', self.listening_port))
        
        print(f"Server listening on port {self.listening_port}")
        return self.socket
        
    
    def create_datagram(self):
        pass
    
    def send_datagram(self):
        pass
    
    def read_datagram(self):
        message, client_address = self.socket.recvfrom(2048)
        
        # TODO remove later
        modified_message = message.decode().upper()
        self.socket.sendto(modified_message.encode(), client_address)
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
    print("Printing args:")
    for arg in vars(args):
        print(arg, getattr(args, arg))
    print("===============")
    # validate_args(args, parser)
    
    tcp_server = SimplexTCPServer(
        args.file, args.listening_port,
        args.address_for_acks, args.port_for_acks
    )
    
    tcp_server.read_datagram()
    return

if __name__ == "__main__":
    main()
