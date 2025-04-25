import threading
import json
from RC6.rc6 import RC6
from RC6 import constants
from frame_message import FrameMessage
import os

class ChatThread(threading.Thread):
    def __init__(self, conn, key, identity):
        super().__init__()
        self.conn = conn
        self.key = key
        self.identity = identity
        self.rc6 = RC6()
        self.running = True
        self.received_files = {}

    def run(self):
        while self.running:
            try:
                data = self.conn.recv(8192).decode().strip()
                decrypted = self.rc6.decrypt(data, self.key, constants.r)
                frame = json.loads(decrypted)
                print(f"[{self.identity}] {frame['file_name'] or 'message'}")
                if frame['file_name']:
                    filename = f"received_{frame['file_name']}"
                    with open(filename, "ab") as f:
                        f.write(bytes(frame['message']))
                else:
                    print(f"Text: {frame['message']}")
            except Exception as e:
                print(f"[ERROR] ChatThread for {self.identity}: {e}")
                self.running = False

    def stop(self):
        self.running = False
        self.conn.close()