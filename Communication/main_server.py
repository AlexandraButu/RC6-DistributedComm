import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from server import TCPServer

if __name__ == "__main__":
    server = TCPServer()
    server.start()
