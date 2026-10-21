"""Transport abstraction package providing socket and in-process communication."""

from sentryscan.transport.framing import (
    FrameReader,
    FrameTooLargeError,
    FramingError,
    encode_frame,
)
from sentryscan.transport.in_process import InProcessTransport, InProcessTransportError
from sentryscan.transport.interface import Transport
from sentryscan.transport.socket_transport import (
    ConnectionClosedError,
    SocketTransportError,
    TCPSocketClient,
    TCPSocketServer,
)

__all__ = [
    "Transport",
    "encode_frame",
    "FrameReader",
    "FramingError",
    "FrameTooLargeError",
    "TCPSocketClient",
    "TCPSocketServer",
    "SocketTransportError",
    "ConnectionClosedError",
    "InProcessTransport",
    "InProcessTransportError",
]
