from dataclasses import dataclass

@dataclass
class FrameMessage:
    message: bytes
    frame: int
    total_frames: int
    file_name: str = None