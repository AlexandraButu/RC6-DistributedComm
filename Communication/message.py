from dataclasses import dataclass

@dataclass
class Message:
    message: str
    by_me: bool
    content_file: bytes = None
    file_name: str = None
