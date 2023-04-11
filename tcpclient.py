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
		help="file that client reads data from"
	)
    parser.add_argument(
		"address_of_udpl", type=int,
		help="emulator's address"
	)
    parser.add_argument(
		"port_number_of_udpl", type=str,
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
    return

if __name__ == "__main__":
    main()
