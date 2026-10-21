"""Length-prefixed JSON TCP socket transport (client and server)."""

from __future__ import annotations

import logging
import queue
import select
import socket
import threading
import time
from typing import Callable

from sentryscan.contracts.message import Message, Performative
from sentryscan.transport.framing import FrameReader, FrameTooLargeError, encode_frame

logger = logging.getLogger(__name__)


class SocketTransportError(Exception):
    """Base exception for socket transport errors."""


class ConnectionClosedError(SocketTransportError):
    """Raised when the remote socket connection is closed unexpectedly."""


class TCPSocketClient:
    """Thread-safe TCP socket client for framed JSON inter-agent messaging."""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 8765,
        default_timeout: float = 5.0,
    ) -> None:
        self.host = host
        self.port = port
        self.default_timeout = default_timeout
        self._sock: socket.socket | None = None
        self._send_lock = threading.Lock()
        self._inbox: queue.Queue[Message] = queue.Queue()
        self._stop_event = threading.Event()
        self._reader_thread: threading.Thread | None = None
        self._frame_reader = FrameReader()

    def connect(self) -> None:
        """Establish direct TCP connection to the server."""
        if self._sock is not None:
            return
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.default_timeout)
        try:
            sock.connect((self.host, self.port))
            # Put socket in non-blocking / selectable mode for background reader
            sock.settimeout(0.2)
            self._sock = sock
            self._stop_event.clear()
            self._reader_thread = threading.Thread(
                target=self._read_loop,
                name="TCPSocketClient-Reader",
                daemon=True,
            )
            self._reader_thread.start()
        except OSError as e:
            sock.close()
            raise SocketTransportError(f"Failed to connect to {self.host}:{self.port}: {e}") from e

    def connect_with_retry(
        self,
        max_retries: int = 5,
        initial_backoff: float = 0.05,
        backoff_multiplier: float = 2.0,
        max_backoff: float = 1.0,
    ) -> bool:
        """Attempt connection with exponential backoff."""
        delay = initial_backoff
        for attempt in range(1, max_retries + 1):
            try:
                self.connect()
                return True
            except SocketTransportError:
                if attempt == max_retries:
                    raise
                time.sleep(delay)
                delay = min(delay * backoff_multiplier, max_backoff)
        return False

    def send(self, message: Message) -> None:
        """Send a Message envelope encoded as a length-prefixed JSON frame."""
        if self._sock is None:
            raise SocketTransportError("Client is not connected")

        payload_bytes = message.to_json().encode("utf-8")
        framed_data = encode_frame(payload_bytes)

        with self._send_lock:
            try:
                self._sock.sendall(framed_data)
            except OSError as e:
                self.close()
                raise SocketTransportError(f"Failed to send message: {e}") from e

    def receive(self, timeout: float | None = 5.0) -> Message | None:
        """Receive the next incoming Message envelope from the inbox queue."""
        try:
            return self._inbox.get(timeout=timeout)
        except queue.Empty:
            return None

    def _read_loop(self) -> None:
        """Background thread reading chunks from socket and buffering frames."""
        while not self._stop_event.is_set() and self._sock is not None:
            try:
                # Use select to check for readability
                r_ready, _, _ = select.select([self._sock], [], [], 0.2)
                if not r_ready:
                    continue

                chunk = self._sock.recv(4096)
                if not chunk:
                    # Server closed connection
                    break

                frames = self._frame_reader.feed(chunk)
                for frame in frames:
                    try:
                        msg_str = frame.decode("utf-8")
                        msg = Message.from_json(msg_str)
                        self._inbox.put(msg)
                    except Exception as err:
                        logger.warning("Failed to decode incoming message frame: %s", err)
            except (OSError, FrameTooLargeError) as err:
                logger.debug("Socket read loop error: %s", err)
                break

    def close(self) -> None:
        """Close connection and terminate reader thread."""
        self._stop_event.set()
        if self._sock is not None:
            try:
                self._sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None

        if self._reader_thread and self._reader_thread.is_alive():
            if threading.current_thread() != self._reader_thread:
                self._reader_thread.join(timeout=1.0)
            self._reader_thread = None


class TCPSocketServer:
    """Thread-safe TCP socket server handling framed JSON messages."""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 8765,
        message_handler: Callable[[Message], Message | None] | None = None,
    ) -> None:
        self.host = host
        self.port = port
        self.message_handler = message_handler
        self._server_sock: socket.socket | None = None
        self._bound_port: int = port
        self._stop_event = threading.Event()
        self._listener_thread: threading.Thread | None = None
        self._client_threads: list[threading.Thread] = []
        self._clients_lock = threading.Lock()
        self._clients: list[socket.socket] = []
        self.incoming_messages: queue.Queue[Message] = queue.Queue()

    @property
    def bound_port(self) -> int:
        """Return the actual bound port (useful when binding to ephemeral port 0)."""
        return self._bound_port

    def start(self) -> None:
        """Bind and start listener thread."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.host, self.port))
        sock.listen(10)
        sock.settimeout(0.5)

        self._server_sock = sock
        self._bound_port = sock.getsockname()[1]
        self._stop_event.clear()

        self._listener_thread = threading.Thread(
            target=self._listen_loop,
            name="TCPSocketServer-Listener",
            daemon=True,
        )
        self._listener_thread.start()

    def _listen_loop(self) -> None:
        """Accept new client connections in a background thread."""
        while not self._stop_event.is_set() and self._server_sock is not None:
            try:
                client_sock, _ = self._server_sock.accept()
                with self._clients_lock:
                    self._clients.append(client_sock)
                t = threading.Thread(
                    target=self._client_handler,
                    args=(client_sock,),
                    name=f"TCPSocketServer-Client-{client_sock.fileno()}",
                    daemon=True,
                )
                self._client_threads.append(t)
                t.start()
            except socket.timeout:
                continue
            except OSError:
                break

    def _client_handler(self, client_sock: socket.socket) -> None:
        """Handle incoming data stream for a single client connection."""
        reader = FrameReader()
        client_sock.settimeout(0.2)
        while not self._stop_event.is_set():
            try:
                r_ready, _, _ = select.select([client_sock], [], [], 0.2)
                if not r_ready:
                    continue

                chunk = client_sock.recv(4096)
                if not chunk:
                    break

                frames = reader.feed(chunk)
                for frame in frames:
                    try:
                        msg_str = frame.decode("utf-8")
                        msg = Message.from_json(msg_str)
                        self.incoming_messages.put(msg)

                        # If a message handler is registered, execute and reply
                        if self.message_handler:
                            reply = self.message_handler(msg)
                            if reply is not None:
                                reply_bytes = reply.to_json().encode("utf-8")
                                client_sock.sendall(encode_frame(reply_bytes))
                    except Exception as err:
                        logger.warning("Error processing client frame: %s", err)
                        # Optionally send an error performative back
                        err_reply = Message(
                            message_id=f"err-{int(time.time()*1000)}",
                            run_id="server-err",
                            sender="server",
                            receiver="client",
                            performative=Performative.ERROR,
                            timestamp_utc=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                            nonce=f"nonce-err-{int(time.time()*1000)}",
                            payload={"error": str(err)},
                        )
                        try:
                            client_sock.sendall(encode_frame(err_reply.to_json().encode("utf-8")))
                        except OSError:
                            pass
            except (OSError, FrameTooLargeError):
                break

        with self._clients_lock:
            if client_sock in self._clients:
                self._clients.remove(client_sock)
        try:
            client_sock.close()
        except OSError:
            pass

    def stop(self) -> None:
        """Stop listening and close all active client connections."""
        self._stop_event.set()
        if self._server_sock is not None:
            try:
                self._server_sock.close()
            except OSError:
                pass
            self._server_sock = None

        with self._clients_lock:
            for c in self._clients:
                try:
                    c.close()
                except OSError:
                    pass
            self._clients.clear()

        if self._listener_thread and self._listener_thread.is_alive():
            if threading.current_thread() != self._listener_thread:
                self._listener_thread.join(timeout=1.0)
            self._listener_thread = None
