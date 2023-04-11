import argparse

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
    return

if __name__ == "__main__":
    main()
