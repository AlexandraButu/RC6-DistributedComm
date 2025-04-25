# communication/tcp/client.py
import socket
import threading
import json
from RC6.rc6 import RC6
from RC6.diffie_hellman import DiffieHellman
from RC6 import constants
from frame_message import FrameMessage
import os

class TCPClient:
    def __init__(self, server_ip, server_port, identity):
        self.rc6 = RC6()
        self.dh = DiffieHellman()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((server_ip, server_port))
        self.identity = identity

        print("[DEBUG] Conectat la server...")

        # Primesc p, g, A
        p = int(self.sock.recv(4096).decode().strip())
        print(f"[DEBUG] p={p}")
        g = int(self.sock.recv(4096).decode().strip())
        print(f"[DEBUG] g={g}")
        A = int(self.sock.recv(4096).decode().strip())
        print(f"[DEBUG] A={A}")

        b = self.dh.get_private_key(p)
        B = pow(g, b, p)
        self.sock.sendall(f"{B}\n".encode())
        print(f"[DEBUG] B={B} trimis")

        s = pow(A, b, p)
        self.key = self.rc6.get_key_from_shared_secret(s)

        # TRIMIT Identity
        print(f"[DEBUG] Trimit identity: {self.identity}")
        self.sock.sendall(f"{self.identity}\n".encode())

        # Acum threadul!
        print("[DEBUG] Pornește receive_messages thread")
        threading.Thread(target=self.receive_messages, daemon=True).start()




    def send_message(self, msg, file_name=None):
        if isinstance(msg, str):
            bytes_data = msg.encode()
        else:
            bytes_data = msg

        chunk_size = constants.chunk_size
        total_frames = (len(bytes_data) + chunk_size - 1) // chunk_size
        for i in range(total_frames):
            chunk = bytes_data[i*chunk_size:(i+1)*chunk_size]
            frame = FrameMessage(chunk, i, total_frames, file_name)
            json_data = json.dumps(frame.__dict__)
            encrypted = self.rc6.encrypt(json_data, self.key, constants.r)
            self.sock.sendall(f"{encrypted}\n".encode())

    def send_file(self, file_path):
        file_name = os.path.basename(file_path)
        with open(file_path, "rb") as f:
            file_bytes = f.read()
        self.send_message(file_bytes, file_name=file_name)

    def receive_messages(self):
        print("[DEBUG] Receiving thread started...")
        while True:
            try:
                data = self.sock.recv(8192).decode().strip()
                print("[DEBUG] Raw received:", data)
                decrypted = self.rc6.decrypt(data, self.key, constants.r)
                frame = json.loads(decrypted)
                print(f"[Received] {frame['file_name'] or 'message'}")
                if frame['file_name']:
                    with open(f"received_{frame['file_name']}", "ab") as f:
                        f.write(bytes(frame['message']))
                else:
                    print(f"Text: {frame['message']}")
            except Exception as e:
                print(f"[ERROR] Receiving failed: {e}")
                break

