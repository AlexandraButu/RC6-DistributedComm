import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from client import TCPClient

if __name__ == "__main__":
    import time
    import sys

    if len(sys.argv) < 4:
        print("Usage: python main_client.py <server_ip> <server_port> <identity>")
        exit(1)

    ip = sys.argv[1]
    port = int(sys.argv[2])
    identity = sys.argv[3]

    client = TCPClient(ip, port, identity)
    time.sleep(1)
    while True:
        choice = input("(1) Send text\n(2) Send file\n> ")
        if choice == "1":
            msg = input("Message: ")
            client.send_message(msg)
        elif choice == "2":
            path = input("File path: ")
            client.send_file(path)
        else:
            print("Invalid option.")
