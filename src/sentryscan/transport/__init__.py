"""Transport abstraction package providing socket and in-process communication."""

from sentryscan.transport.framing import FrameReader, FrameTooLargeError, FramingError, encode_frame
from sentryscan.transport.socket_transport import (
    ConnectionClosedError,
    SocketTransportError,
    TCPSocketClient,
    TCPSocketServer,
)

__all__ = [
    "encode_frame",
    "FrameReader",
    "FramingError",
    "FrameTooLargeError",
    "TCPSocketClient",
    "TCPSocketServer",
    "SocketTransportError",
    "ConnectionClosedError",
]
