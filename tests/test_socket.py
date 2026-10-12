"""dcsctp の基本的な動作を確認するテスト。"""

from __future__ import annotations

import dcsctp
import pytest


def _pump(sock: dcsctp.Socket, peer: dcsctp.Socket) -> list[dcsctp.SocketEvent]:
    """片方のソケットのイベントを処理し、パケットを相手に渡す。"""
    events: list[dcsctp.SocketEvent] = []
    while True:
        event = sock.poll_event()
        if event is None:
            break
        events.append(event)
        # 送信パケットは相手ソケットに入力として渡す
        if event.kind == "send_packet" and event.data is not None:
            peer.handle_input(event.data)
    return events


def test_version() -> None:
    """バージョン文字列が取得できること。"""
    version = dcsctp.version()
    assert isinstance(version, str)
    assert len(version) > 0


def test_socket_creation() -> None:
    """ソケットが生成でき、初期状態は Closed であること。"""
    sock = dcsctp.Socket("test")
    assert sock.state() == dcsctp.SocketState.Closed


def test_connect_handshake() -> None:
    """2 ソケット間で SCTP ハンドシェイクが完了すること。"""
    # クライアントとサーバのソケットを生成
    client = dcsctp.Socket("client")
    server = dcsctp.Socket("server")

    # クライアントから接続開始
    client.connect()

    # ハンドシェイクが完了するまでパケットを交換する
    # INIT -> INIT-ACK -> COOKIE-ECHO -> COOKIE-ACK の 4 ウェイ
    for _ in range(10):
        _pump(client, server)
        _pump(server, client)

    # 両方が接続済み状態になっていること
    assert client.state() == dcsctp.SocketState.Connected
    assert server.state() == dcsctp.SocketState.Connected


def test_send_and_receive_message() -> None:
    """接続確立後にメッセージの送受信ができること。"""
    client = dcsctp.Socket("client")
    server = dcsctp.Socket("server")

    # ハンドシェイク
    client.connect()
    for _ in range(10):
        _pump(client, server)
        _pump(server, client)

    assert client.state() == dcsctp.SocketState.Connected

    # クライアントからメッセージ送信 (stream_id=1, ppid=53)
    payload = b"hello dcsctp"
    msg = dcsctp.Message(stream_id=1, ppid=53, payload=payload)
    client.send(msg)

    # パケットを交換して受信側に届ける
    for _ in range(10):
        _pump(client, server)
        _pump(server, client)

    # サーバ側でメッセージが受信できていること
    assert server.messages_ready_count() >= 1
    received = server.get_next_message()
    assert received is not None
    assert received.stream_id == 1
    assert received.ppid == 53
    assert received.payload == payload


def test_options_defaults() -> None:
    """Options のデフォルト値が dcsctp のデフォルトと一致すること。"""
    opts = dcsctp.Options()
    assert opts.local_port == 5000
    assert opts.remote_port == 5000
    assert opts.mtu == 1191
    assert opts.max_message_size == 256 * 1024
    # dcsctp 0.1.15 で追加された設定のデフォルト値
    assert opts.immediate_sack_under_cwnd_mtus == 10
    assert opts.zero_checksum_alternate_error_detection_method == 0


def test_options_custom() -> None:
    """Options にキーワード引数でカスタム値を設定できること。"""
    opts = dcsctp.Options(local_port=9000, remote_port=9001, mtu=1400)
    assert opts.local_port == 9000
    assert opts.remote_port == 9001
    assert opts.mtu == 1400


def test_send_empty_payload_raises() -> None:
    """空ペイロードの送信は ValueError になること。"""
    sock = dcsctp.Socket("test")
    msg = dcsctp.Message(stream_id=0, ppid=0, payload=b"")
    with pytest.raises(ValueError, match="empty"):
        sock.send(msg)


def test_shutdown() -> None:
    """接続確立後にシャットダウンできること。"""
    client = dcsctp.Socket("client")
    server = dcsctp.Socket("server")

    # ハンドシェイク
    client.connect()
    for _ in range(10):
        _pump(client, server)
        _pump(server, client)

    assert client.state() == dcsctp.SocketState.Connected

    # グレースフルシャットダウン
    client.shutdown()
    for _ in range(10):
        _pump(client, server)
        _pump(server, client)

    # 両方が Closed になっていること
    assert client.state() == dcsctp.SocketState.Closed
    assert server.state() == dcsctp.SocketState.Closed
