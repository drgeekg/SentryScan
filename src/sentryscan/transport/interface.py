"""Abstract Transport interface protocol for agent communication."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from sentryscan.contracts.message import Message


@runtime_checkable
class Transport(Protocol):
    """Protocol for sending and receiving Message envelopes."""

    def send(self, message: Message) -> None:
        """Send a Message envelope over the transport."""
        ...

    def receive(self, timeout: float | None = 5.0) -> Message | None:
        """Receive the next incoming Message envelope, blocking up to timeout seconds."""
        ...

    def close(self) -> None:
        """Close the transport and release associated resources."""
        ...
