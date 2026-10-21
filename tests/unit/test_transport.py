"""Unit tests covering transport framing, sockets, timeouts, errors, and reconnects."""

from __future__ import annotations

import socket
import struct
import threading
import time

import pytest

from sentryscan.contracts.message import Message, Performative
from sentryscan.transport.framing import (
    FrameReader,
    FrameTooLargeError,
    encode_frame,
)
from sentryscan.transport.in_process import InProcessTransport, InProcessTransportError
from sentryscan.transport.socket_transport import (
    SocketTransportError,
    TCPSocketClient,
    TCPSocketServer,
)


def _make_sample_msg(seq: int = 1, text: str = "hello") -> Message:
    return Message(
        message_id=f"msg-{seq:03d}",
        run_id="run-transport-test",
        sender="test-sender",
        receiver="test-receiver",
        performative=Performative.TASK_REQUEST,
        timestamp_utc="2026-10-21T06:00:00Z",
        nonce=f"nonce-{seq:04d}",
        payload={"text": text},
    )


# ==============================================================================
# Framing Tests
# ==============================================================================


def test_encode_frame_structure():
    payload = b'{"hello": "world"}'
    framed = encode_frame(payload)
    assert len(framed) == 4 + len(payload)
    length = struct.unpack("!I", framed[:4])[0]
    assert length == len(payload)
    assert framed[4:] == payload


def test_encode_frame_exceeds_max_size():
    payload = b"x" * 100
    with pytest.raises(FrameTooLargeError):
        encode_frame(payload, max_frame_size=50)


def test_frame_reader_complete_frame():
    reader = FrameReader(max_frame_size=1024)
    framed = encode_frame(b"test-payload")
    frames = reader.feed(framed)
    assert frames == [b"test-payload"]
    assert reader.buffer_size == 0


def test_frame_reader_partial_chunks():
    reader = FrameReader(max_frame_size=1024)
    framed = encode_frame(b"partial-stream-payload")

    # Feed byte by byte
    all_extracted = []
    for byte in framed:
        frames = reader.feed(bytes([byte]))
        all_extracted.extend(frames)

    assert all_extracted == [b"partial-stream-payload"]
    assert reader.buffer_size == 0


def test_frame_reader_multiple_frames_in_one_chunk():
    reader = FrameReader(max_frame_size=1024)
    chunk = encode_frame(b"frame-1") + encode_frame(b"frame-2") + encode_frame(b"frame-3")
    frames = reader.feed(chunk)
    assert frames == [b"frame-1", b"frame-2", b"frame-3"]
    assert reader.buffer_size == 0


def test_frame_reader_oversized_declared_length():
    reader = FrameReader(max_frame_size=100)
    fake_header = struct.pack("!I", 500)
    with pytest.raises(FrameTooLargeError):
        reader.feed(fake_header)
    assert reader.buffer_size == 0


# ==============================================================================
# In-Process Transport Tests
# ==============================================================================


def test_in_process_transport_pair():
    peer_a, peer_b = InProcessTransport.create_pair()

    msg1 = _make_sample_msg(1, "A to B")
    peer_a.send(msg1)

    received_by_b = peer_b.receive(timeout=1.0)
    assert received_by_b is not None
    assert received_by_b.payload["text"] == "A to B"

    msg2 = _make_sample_msg(2, "B to A")
    peer_b.send(msg2)

    received_by_a = peer_a.receive(timeout=1.0)
    assert received_by_a is not None
    assert received_by_a.payload["text"] == "B to A"

    peer_a.close()
    peer_b.close()
    assert peer_a.is_closed
    assert peer_b.is_closed

    with pytest.raises(InProcessTransportError):
        peer_a.send(msg1)


def test_in_process_transport_timeout():
    peer_a, peer_b = InProcessTransport.create_pair()
    res = peer_a.receive(timeout=0.05)
    assert res is None
    peer_a.close()
    peer_b.close()


# ==============================================================================
# TCP Socket Transport Tests
# ==============================================================================


def test_tcp_socket_roundtrip_request_reply():
    def echo_handler(msg: Message) -> Message | None:
        return Message(
            message_id="reply-001",
            run_id=msg.run_id,
            sender="server",
            receiver=msg.sender,
            performative=Performative.TASK_RESULT,
            timestamp_utc="2026-10-21T06:05:00Z",
            nonce="nonce-reply-001",
            task_id=msg.task_id,
            payload={"echo": msg.payload["text"]},
        )

    server = TCPSocketServer(host="127.0.0.1", port=0, message_handler=echo_handler)
    server.start()
    port = server.bound_port

    client = TCPSocketClient(host="127.0.0.1", port=port)
    try:
        client.connect()
        client.send(_make_sample_msg(1, "ping-pong"))

        reply = client.receive(timeout=2.0)
        assert reply is not None
        assert reply.performative == Performative.TASK_RESULT
        assert reply.payload["echo"] == "ping-pong"
    finally:
        client.close()
        server.stop()


def test_tcp_socket_timeout_when_idle():
    server = TCPSocketServer(host="127.0.0.1", port=0)
    server.start()
    port = server.bound_port

    client = TCPSocketClient(host="127.0.0.1", port=port)
    try:
        client.connect()
        # No message sent, receive should timeout cleanly
        res = client.receive(timeout=0.1)
        assert res is None
    finally:
        client.close()
        server.stop()


def test_tcp_socket_malformed_json_frame_resilience():
    server = TCPSocketServer(host="127.0.0.1", port=0)
    server.start()
    port = server.bound_port

    # Connect raw socket and send invalid JSON payload in a valid frame
    raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        raw_sock.connect(("127.0.0.1", port))
        bad_json = b"THIS IS NOT VALID JSON {"
        raw_sock.sendall(encode_frame(bad_json))

        # Server should catch error and reply with ERROR performative without crashing
        raw_sock.settimeout(2.0)
        resp_len_bytes = raw_sock.recv(4)
        resp_len = struct.unpack("!I", resp_len_bytes)[0]
        resp_payload = raw_sock.recv(resp_len)
        err_msg = Message.from_json(resp_payload.decode("utf-8"))
        assert err_msg.performative == Performative.ERROR
    finally:
        raw_sock.close()
        server.stop()


def test_tcp_socket_client_reconnect_backoff():
    # Attempt connecting before server starts
    # Find a free port
    temp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    temp_sock.bind(("127.0.0.1", 0))
    free_port = temp_sock.getsockname()[1]
    temp_sock.close()

    client = TCPSocketClient(host="127.0.0.1", port=free_port)

    # In a background thread, start server after a short delay
    server_holder: list[TCPSocketServer] = []

    def delayed_server_start():
        time.sleep(0.15)
        srv = TCPSocketServer(host="127.0.0.1", port=free_port)
        srv.start()
        server_holder.append(srv)

    t = threading.Thread(target=delayed_server_start, daemon=True)
    t.start()

    try:
        connected = client.connect_with_retry(
            max_retries=5, initial_backoff=0.05, backoff_multiplier=1.5
        )
        assert connected is True
        client.send(_make_sample_msg(1, "reconnected"))
    finally:
        client.close()
        if server_holder:
            server_holder[0].stop()
        t.join(timeout=1.0)


def test_tcp_socket_client_unconnected_send_raises():
    client = TCPSocketClient(host="127.0.0.1", port=9999)
    with pytest.raises(SocketTransportError):
        client.send(_make_sample_msg(1, "fail"))
