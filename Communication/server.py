# communication/tcp/server.py
import socket
import threading
import json
from RC6.rc6 import RC6
from RC6.diffie_hellman import DiffieHellman
from RC6 import constants
from chat_thread import ChatThread

users = {}

class TCPServer:
    def __init__(self, host='0.0.0.0', port=0):
        self.rc6 = RC6()
        self.dh = DiffieHellman()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind((host, port))
        self.sock.listen()
        self.host, self.port = self.sock.getsockname()
        print(f"Server running on {self.host}:{self.port}")

    def start(self):
        while True:
            client_sock, addr = self.sock.accept()
            print(f"Accepted connection from {addr}")
            thread = threading.Thread(target=self.handle_client, args=(client_sock,))
            thread.start()

    def handle_client(self, client_sock):
        try:
            conn = client_sock
            conn_file = conn.makefile('rwb')

            # DH key exchange
            p = self.dh.get_p(bits=constants.size)
            g = self.dh.get_g(p)
            a = self.dh.get_private_key(p)
            A = pow(g, a, p)

            conn.sendall(f"{p}\n{g}\n{A}\n".encode())
            B = int(conn.recv(4096).decode().strip())
            s = pow(B, a, p)

            key = self.rc6.get_key_from_shared_secret(s)

            # Identify client
            identity = conn.recv(1024).decode().strip()
            chat_thread = ChatThread(conn, key, identity)
            users[identity] = chat_thread
            chat_thread.start()

        except Exception as e:
            print(f"[ERROR] {e}")
            client_sock.close()

