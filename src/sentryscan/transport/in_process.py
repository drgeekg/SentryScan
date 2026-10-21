"""In-process thread-safe queue-backed Transport implementation."""

from __future__ import annotations

import queue
import threading

from sentryscan.contracts.message import Message


class InProcessTransportError(Exception):
    """Raised when an operation fails on an InProcessTransport."""


class InProcessTransport:
    """Thread-safe in-process transport connecting two peers via synchronized queues."""

    def __init__(
        self,
        inbox: queue.Queue[Message] | None = None,
        peer_inbox: queue.Queue[Message] | None = None,
    ) -> None:
        self._inbox: queue.Queue[Message] = inbox if inbox is not None else queue.Queue()
        self._peer_inbox: queue.Queue[Message] | None = peer_inbox
        self._is_closed = threading.Event()

    @classmethod
    def create_pair(cls) -> tuple[InProcessTransport, InProcessTransport]:
        """Create a full-duplex pair of connected in-process transports."""
        q_a_to_b: queue.Queue[Message] = queue.Queue()
        q_b_to_a: queue.Queue[Message] = queue.Queue()

        peer_a = cls(inbox=q_b_to_a, peer_inbox=q_a_to_b)
        peer_b = cls(inbox=q_a_to_b, peer_inbox=q_b_to_a)
        return peer_a, peer_b

    def connect_peer(self, peer: InProcessTransport) -> None:
        """Connect this transport directly to a peer transport."""
        self._peer_inbox = peer._inbox
        peer._peer_inbox = self._inbox

    def send(self, message: Message) -> None:
        """Send a Message envelope to the connected peer's inbox."""
        if self._is_closed.is_set():
            raise InProcessTransportError("Cannot send on a closed transport")
        if self._peer_inbox is None:
            raise InProcessTransportError("No connected peer transport")

        self._peer_inbox.put(message)

    def receive(self, timeout: float | None = 5.0) -> Message | None:
        """Receive the next incoming Message envelope from this transport's inbox."""
        if self._is_closed.is_set():
            raise InProcessTransportError("Cannot receive on a closed transport")
        try:
            return self._inbox.get(timeout=timeout)
        except queue.Empty:
            return None

    def close(self) -> None:
        """Close this transport."""
        self._is_closed.set()

    @property
    def is_closed(self) -> bool:
        """Return True if this transport has been closed."""
        return self._is_closed.is_set()
