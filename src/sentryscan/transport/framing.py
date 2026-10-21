"""Framing protocol: 4-byte big-endian length-prefixed binary framing."""

from __future__ import annotations

import struct

DEFAULT_MAX_FRAME_SIZE = 1_048_576  # 1 MB


class FramingError(Exception):
    """Base exception for framing protocol errors."""


class FrameTooLargeError(FramingError):
    """Raised when an incoming or outgoing frame exceeds the maximum allowed size."""


def encode_frame(payload: bytes, max_frame_size: int = DEFAULT_MAX_FRAME_SIZE) -> bytes:
    """Encode a payload with a 4-byte big-endian length prefix."""
    payload_len = len(payload)
    if payload_len > max_frame_size:
        raise FrameTooLargeError(
            f"Payload size {payload_len} exceeds maximum allowed frame size {max_frame_size}"
        )
    return struct.pack("!I", payload_len) + payload


class FrameReader:
    """Streaming buffer that parses length-prefixed frames from chunked byte streams."""

    def __init__(self, max_frame_size: int = DEFAULT_MAX_FRAME_SIZE) -> None:
        self.max_frame_size = max_frame_size
        self._buffer = bytearray()

    def feed(self, chunk: bytes) -> list[bytes]:
        """Feed new bytes into buffer and return all complete frames extracted."""
        self._buffer.extend(chunk)
        frames: list[bytes] = []

        while len(self._buffer) >= 4:
            frame_len = struct.unpack("!I", self._buffer[:4])[0]
            if frame_len > self.max_frame_size:
                # Buffer contains invalid or malicious frame length
                self._buffer.clear()
                raise FrameTooLargeError(
                    f"Declared frame length {frame_len} exceeds maximum {self.max_frame_size}"
                )

            total_needed = 4 + frame_len
            if len(self._buffer) < total_needed:
                # Incomplete frame, wait for more chunks
                break

            # Complete frame ready
            frame_bytes = bytes(self._buffer[4:total_needed])
            del self._buffer[:total_needed]
            frames.append(frame_bytes)

        return frames

    def clear(self) -> None:
        """Clear unparsed bytes from buffer."""
        self._buffer.clear()

    @property
    def buffer_size(self) -> int:
        """Return the count of unparsed bytes currently in buffer."""
        return len(self._buffer)
