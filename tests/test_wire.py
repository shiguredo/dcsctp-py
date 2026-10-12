"""ソケットが送受信する生の SCTP パケットを低レイヤーで検証するテスト。

`dcsctp.Packet` でパケットを解析・組み立てし、ハンドシェイク・データ転送・
ハートビート・ストリームリセット・シャットダウンのバイト列を直接検証する。
"""

from typing import NamedTuple

import dcsctp
import pytest


class _Handshake(NamedTuple):
    """ハンドシェイクで交換されたパケットを方向ごとに保持する。"""

    init_packets: list[dcsctp.Packet]
    init_ack_packets: list[dcsctp.Packet]
    cookie_echo_packets: list[dcsctp.Packet]
    cookie_ack_packets: list[dcsctp.Packet]


def _drain(
    sock: dcsctp.Socket, peer: dcsctp.Socket | None = None
) -> tuple[list[dcsctp.SocketEvent], list[dcsctp.Packet]]:
    """ソケットのイベントを処理し、送信パケットを解析して相手へ入力する。"""
    events: list[dcsctp.SocketEvent] = []
    packets: list[dcsctp.Packet] = []
    while True:
        event = sock.poll_event()
        if event is None:
            break
        events.append(event)
        # 送信パケットは解析してから相手ソケットへ渡す
        if event.kind == "send_packet" and event.data is not None:
            packet = dcsctp.Packet.parse(event.data)
            packets.append(packet)
            if peer is not None:
                peer.handle_input(event.data)
    return events, packets


def _connect_pair(
    options: dcsctp.Options | None = None,
) -> tuple[dcsctp.Socket, dcsctp.Socket, _Handshake]:
    """ハンドシェイクをパケット単位で進めて接続済みのソケットペアを返す。"""
    client = dcsctp.Socket("client", options)
    server = dcsctp.Socket("server", options)

    # INIT -> INIT-ACK -> COOKIE-ECHO -> COOKIE-ACK の順に 1 往復ずつ進める
    client.connect()
    init_packets = _drain(client, server)[1]
    init_ack_packets = _drain(server, client)[1]
    cookie_echo_packets = _drain(client, server)[1]
    cookie_ack_packets = _drain(server, client)[1]

    # 接続完了イベントなどを処理し切る
    for _ in range(3):
        _drain(client, server)
        _drain(server, client)

    handshake = _Handshake(
        init_packets=init_packets,
        init_ack_packets=init_ack_packets,
        cookie_echo_packets=cookie_echo_packets,
        cookie_ack_packets=cookie_ack_packets,
    )
    if client.state() != dcsctp.SocketState.Connected:
        raise AssertionError(f"client is not connected: {client.state()}")
    if server.state() != dcsctp.SocketState.Connected:
        raise AssertionError(f"server is not connected: {server.state()}")
    return client, server, handshake


def test_handshake_packets() -> None:
    """4 ウェイハンドシェイクのパケット列をバイトレベルで検証する。"""
    client, server, handshake = _connect_pair()

    # 1. INIT: 検証タグは 0 で送信される (RFC 9260 Section 3.3.2)
    assert len(handshake.init_packets) == 1
    init_packet = handshake.init_packets[0]
    assert init_packet.source_port == 5000
    assert init_packet.destination_port == 5000
    assert init_packet.verification_tag == 0
    assert init_packet.has_valid_checksum()

    init = init_packet.chunks[0]
    assert isinstance(init, dcsctp.InitChunk)
    assert init.initiate_tag != 0
    assert init.initial_tsn != 0
    # デフォルトでは双方 65535 ストリームを通知する
    assert init.outbound_streams == 65535
    assert init.inbound_streams == 65535
    # dcsctp は Forward TSN 対応と RE-CONFIG / FORWARD-TSN の対応を通知する
    assert any(
        isinstance(parameter, dcsctp.ForwardTsnSupportedParameter) for parameter in init.parameters
    )
    supported_extensions = next(
        parameter
        for parameter in init.parameters
        if isinstance(parameter, dcsctp.SupportedExtensionsParameter)
    )
    assert dcsctp.ChunkType.RE_CONFIG in supported_extensions.chunk_types
    assert dcsctp.ChunkType.FORWARD_TSN in supported_extensions.chunk_types

    # 2. INIT-ACK: クライアントの initiate_tag を検証タグに使う (RFC 9260 Section 3.3.3)
    assert len(handshake.init_ack_packets) == 1
    init_ack_packet = handshake.init_ack_packets[0]
    assert init_ack_packet.verification_tag == init.initiate_tag
    assert init_ack_packet.has_valid_checksum()

    init_ack = init_ack_packet.chunks[0]
    assert isinstance(init_ack, dcsctp.InitAckChunk)
    assert init_ack.initiate_tag != 0
    state_cookie = next(
        parameter
        for parameter in init_ack.parameters
        if isinstance(parameter, dcsctp.StateCookieParameter)
    )
    assert state_cookie.cookie != b""

    # 3. COOKIE-ECHO: サーバーの initiate_tag を検証タグに使い、同じ Cookie を返す
    assert len(handshake.cookie_echo_packets) == 1
    cookie_echo_packet = handshake.cookie_echo_packets[0]
    assert cookie_echo_packet.verification_tag == init_ack.initiate_tag

    cookie_echo = cookie_echo_packet.chunks[0]
    assert isinstance(cookie_echo, dcsctp.CookieEchoChunk)
    assert cookie_echo.cookie == state_cookie.cookie

    # 4. COOKIE-ACK: クライアントの initiate_tag を検証タグに使う
    assert len(handshake.cookie_ack_packets) == 1
    cookie_ack_packet = handshake.cookie_ack_packets[0]
    assert cookie_ack_packet.verification_tag == init.initiate_tag
    assert isinstance(cookie_ack_packet.chunks[0], dcsctp.CookieAckChunk)

    # ハンドシェイク完了後は双方 Connected になる
    assert client.state() == dcsctp.SocketState.Connected
    assert server.state() == dcsctp.SocketState.Connected


def test_init_advertises_configured_stream_counts() -> None:
    """INIT のストリーム数が Options の announced 値と一致すること。"""
    options = dcsctp.Options(
        announced_maximum_incoming_streams=123, announced_maximum_outgoing_streams=456
    )

    _, _, handshake = _connect_pair(options)

    init = handshake.init_packets[0].chunks[0]
    assert isinstance(init, dcsctp.InitChunk)
    assert init.outbound_streams == 456
    assert init.inbound_streams == 123


def test_peer_implementation_is_detected() -> None:
    """ハンドシェイク後にピアの SCTP 実装が判定されること。"""
    client, _, _ = _connect_pair()

    metrics = client.get_metrics()
    assert metrics is not None
    # INIT-ACK の State Cookie の解析から dcsctp (Rust) と判定される
    assert metrics.peer_implementation == dcsctp.SctpImplementation.DcsctpRs


def test_options_getter_returns_effective_options() -> None:
    """Socket.options() が設定済みの値を返すこと。"""
    options = dcsctp.Options(mtu=1200, announced_maximum_incoming_streams=7)
    client = dcsctp.Socket("client", options)

    assert client.options().mtu == 1200
    assert client.options().announced_maximum_incoming_streams == 7


def test_zero_checksum_negotiation() -> None:
    """zero checksum を両端で有効にすると CRC なしのパケットが使われること (RFC 9653)。"""
    options = dcsctp.Options(zero_checksum_alternate_error_detection_method=1)
    client, server, handshake = _connect_pair(options)

    # INIT / INIT-ACK で Zero Checksum Acceptable パラメータを通知する
    for packets in (handshake.init_packets, handshake.init_ack_packets):
        chunk = packets[0].chunks[0]
        assert isinstance(chunk, dcsctp.InitChunk)
        parameter = next(
            parameter
            for parameter in chunk.parameters
            if isinstance(parameter, dcsctp.ZeroChecksumAcceptableParameter)
        )
        assert parameter.error_detection_method == 1

    # 交渉が完了すると uses_zero_checksum が真になる
    client_metrics = client.get_metrics()
    assert client_metrics is not None
    assert client_metrics.uses_zero_checksum
    server_metrics = server.get_metrics()
    assert server_metrics is not None
    assert server_metrics.uses_zero_checksum

    # 送信パケットのチェックサムは 0 になり、相手はそれを受け入れる
    client.send(dcsctp.Message(stream_id=1, ppid=53, payload=b"zero checksum"))
    _, data_packets = _drain(client, server)

    assert data_packets[0].checksum == 0
    assert not data_packets[0].has_valid_checksum()
    assert server.messages_ready_count() == 1
    message = server.get_next_message()
    assert message is not None
    assert message.payload == b"zero checksum"


def test_data_and_sack_packets() -> None:
    """DATA チャンクと SACK チャンクのフィールドを直接検証する。"""
    client, server, _ = _connect_pair()

    # メッセージ送信で DATA チャンクが 1 個送られる
    client.send(dcsctp.Message(stream_id=1, ppid=53, payload=b"low level"))
    _, data_packets = _drain(client, server)

    assert len(data_packets) == 1
    data = data_packets[0].chunks[0]
    assert isinstance(data, dcsctp.DataChunk)
    assert data.stream_id == 1
    assert data.ppid == 53
    assert data.payload == b"low level"
    assert data.beginning
    assert data.end
    assert not data.unordered
    assert not data.immediate_ack

    # 受信側は DATA の TSN を累積 ACK した SACK を返す (RFC 9260 Section 3.3.4)
    _, sack_packets = _drain(server, client)

    assert len(sack_packets) == 1
    sack = sack_packets[0].chunks[0]
    assert isinstance(sack, dcsctp.SackChunk)
    assert sack.cumulative_tsn_ack == data.tsn
    assert sack.duplicate_tsns == []


def test_fragmented_data_chunks() -> None:
    """メッセージが MTU に合わせて複数の DATA チャンクへ分割されること。"""
    options = dcsctp.Options(mtu=200)
    client, server, _ = _connect_pair(options)

    payload = bytes(range(256)) * 2
    client.send(dcsctp.Message(stream_id=3, ppid=51, payload=payload))
    _, packets = _drain(client, server)

    chunks = [
        chunk
        for packet in packets
        for chunk in packet.chunks
        if isinstance(chunk, dcsctp.DataChunk)
    ]
    assert len(chunks) == 3
    # 最初のチャンクだけ B ビット、最後のチャンクだけ E ビットが立つ (RFC 9260 Section 3.3.1)
    assert [chunk.beginning for chunk in chunks] == [True, False, False]
    assert [chunk.end for chunk in chunks] == [False, False, True]
    # TSN は連番になる
    assert [chunk.tsn for chunk in chunks] == [chunks[0].tsn + index for index in range(3)]
    # 分割前のペイロードに復元できる
    assert b"".join(chunk.payload for chunk in chunks) == payload

    # 受信側ではメッセージとして再構成される
    for _ in range(3):
        _drain(server, client)
        _drain(client, server)
    message = server.get_next_message()
    assert message is not None
    assert message.stream_id == 3
    assert message.ppid == 51
    assert message.payload == payload


def test_partial_reliability_sends_i_forward_tsn() -> None:
    """ライフタイム切れのメッセージが I-FORWARD-TSN でスキップされること (RFC 8260)。"""
    options = dcsctp.Options(enable_message_interleaving=True)
    client, server, _ = _connect_pair(options)

    # 即時にライフタイム切れするメッセージを送ると I-DATA が生成される
    client.send(
        dcsctp.Message(stream_id=1, ppid=53, payload=b"expire me"),
        dcsctp.SendOptions(lifetime_ms=0),
    )
    _, data_packets = _drain(client)

    idata = data_packets[0].chunks[0]
    assert isinstance(idata, dcsctp.IDataChunk)
    assert idata.stream_id == 1
    assert idata.mid == 0
    assert idata.ppid == 53
    assert idata.payload == b"expire me"

    # 時間を進めると期限切れを通知する I-FORWARD-TSN が送られる
    client.advance_time(1000)
    _, forward_packets = _drain(client)

    iforward = forward_packets[0].chunks[0]
    assert isinstance(iforward, dcsctp.IForwardTsnChunk)
    assert iforward.new_cumulative_tsn == idata.tsn
    assert iforward.skipped_streams == [dcsctp.IForwardTsnSkippedStream(1, False, 0)]

    # I-DATA を受け取っていなくても I-FORWARD-TSN だけでスキップできる
    server.handle_input(forward_packets[0].to_bytes())
    assert server.messages_ready_count() == 0

    # スキップ後のメッセージは TSN が飛んでいても受信できる
    client.send(dcsctp.Message(stream_id=2, ppid=53, payload=b"next message"))
    _, next_packets = _drain(client, server)

    next_data = next_packets[0].chunks[0]
    assert isinstance(next_data, dcsctp.IDataChunk)
    assert next_data.tsn == idata.tsn + 1
    assert server.messages_ready_count() == 1
    message = server.get_next_message()
    assert message is not None
    assert message.stream_id == 2
    assert message.payload == b"next message"


def test_retransmission_after_packet_loss() -> None:
    """パケットロス後に同じ TSN が再送され、メトリクスに現れること。"""
    client, _, _ = _connect_pair()

    # 相手に渡さずロスさせる
    client.send(dcsctp.Message(stream_id=1, ppid=53, payload=b"lost"))
    _, packets = _drain(client)

    data = packets[0].chunks[0]
    assert isinstance(data, dcsctp.DataChunk)
    metrics = client.get_metrics()
    assert metrics is not None
    assert metrics.unack_data_count == 1
    assert metrics.rtx_packets_count == 0

    # RTO 経過で同じ TSN が再送される (RFC 9260 Section 6.3.3)
    client.advance_time(dcsctp.Options().rto_initial_ms)
    _, retransmission_packets = _drain(client)

    retransmitted = retransmission_packets[0].chunks[0]
    assert isinstance(retransmitted, dcsctp.DataChunk)
    assert retransmitted.tsn == data.tsn
    assert retransmitted.payload == data.payload
    metrics = client.get_metrics()
    assert metrics is not None
    assert metrics.rtx_packets_count == 1


def test_heartbeat_injection_returns_heartbeat_ack() -> None:
    """HEARTBEAT を注入すると HEARTBEAT ACK が返ること (RFC 9260 Section 3.3.5)。"""
    client, server, handshake = _connect_pair()
    server_initiate_tag = _initiate_tag(handshake.init_ack_packets)
    client_initiate_tag = _initiate_tag(handshake.init_packets)

    # client -> server のパケットはサーバーの initiate_tag を検証タグに持つ
    heartbeat = dcsctp.Packet(
        source_port=5000,
        destination_port=5000,
        verification_tag=server_initiate_tag,
        chunks=[dcsctp.HeartbeatChunk(parameters=[dcsctp.HeartbeatInfoParameter(b"\x11" * 8)])],
    )
    server.handle_input(heartbeat.to_bytes())
    _, packets = _drain(server, client)

    assert len(packets) == 1
    # 応答はクライアントの initiate_tag を検証タグに使う
    assert packets[0].verification_tag == client_initiate_tag
    ack = packets[0].chunks[0]
    assert isinstance(ack, dcsctp.HeartbeatAckChunk)
    info = ack.parameters[0]
    assert isinstance(info, dcsctp.HeartbeatInfoParameter)
    assert info.info == b"\x11" * 8


def test_unknown_chunk_injection_reports_error() -> None:
    """未知のチャンクを注入すると Unrecognized Chunk Type の ERROR が返ること。"""
    client, server, handshake = _connect_pair()
    server_initiate_tag = _initiate_tag(handshake.init_ack_packets)

    unknown_chunk = dcsctp.UnknownChunk(0x42, b"\x01\x02\x03\x04")
    packet = dcsctp.Packet(
        source_port=5000,
        destination_port=5000,
        verification_tag=server_initiate_tag,
        chunks=[unknown_chunk],
    )
    server.handle_input(packet.to_bytes())
    events, packets = _drain(server, client)

    # dcsctp はパース失敗を error イベントで通知する
    assert any(
        event.kind == "error" and event.error_kind == dcsctp.ErrorKind.ParseFailed
        for event in events
    )

    # 問題のチャンク全体を含む Unrecognized Chunk Type エラー原因が返る
    assert len(packets) == 1
    error_chunk = packets[0].chunks[0]
    assert isinstance(error_chunk, dcsctp.ErrorChunk)
    cause = error_chunk.error_causes[0]
    assert isinstance(cause, dcsctp.UnrecognizedChunkErrorCause)
    assert cause.chunk == unknown_chunk.to_bytes()
    assert server.state() == dcsctp.SocketState.Connected


def test_wrong_verification_tag_is_ignored() -> None:
    """検証タグが一致しないパケットは破棄されること (RFC 9260 Section 3.1)。"""
    client, server, _ = _connect_pair()

    heartbeat = dcsctp.Packet(
        source_port=5000,
        destination_port=5000,
        verification_tag=0xDEADBEEF,
        chunks=[dcsctp.HeartbeatChunk(parameters=[dcsctp.HeartbeatInfoParameter(b"\x00" * 8)])],
    )
    server.handle_input(heartbeat.to_bytes())
    events, packets = _drain(server, client)

    assert packets == []
    assert any(event.kind == "error" for event in events)
    assert server.state() == dcsctp.SocketState.Connected


def test_broken_checksum_is_rejected() -> None:
    """チェックサムが壊れたパケットは破棄されること (RFC 9260 Section 3.1)。"""
    client, server, handshake = _connect_pair()
    server_initiate_tag = _initiate_tag(handshake.init_ack_packets)

    heartbeat = dcsctp.Packet(
        source_port=5000,
        destination_port=5000,
        verification_tag=server_initiate_tag,
        chunks=[dcsctp.HeartbeatChunk(parameters=[dcsctp.HeartbeatInfoParameter(b"\x22" * 8)])],
    )
    server.handle_input(heartbeat.to_bytes(checksum=0))
    events, packets = _drain(server, client)

    assert packets == []
    assert any(event.kind == "error" for event in events)
    assert server.state() == dcsctp.SocketState.Connected


def test_stream_reset_packets() -> None:
    """ストリームリセットで RE-CONFIG チャンクが交換されること (RFC 6525)。"""
    client, server, _ = _connect_pair()

    # 先に 1 メッセージ送って TSN を進めておく
    client.send(dcsctp.Message(stream_id=1, ppid=53, payload=b"before reset"))
    _drain(client, server)
    _drain(server, client)

    client.reset_streams([1])
    _, reset_packets = _drain(client, server)

    reconfig = reset_packets[0].chunks[0]
    assert isinstance(reconfig, dcsctp.ReConfigChunk)
    request = reconfig.parameters[0]
    assert isinstance(request, dcsctp.OutgoingSsnResetRequestParameter)
    assert request.stream_ids == [1]

    # サーバーはリセット要求を受け入れ、応答パラメータ付きの RE-CONFIG を返す
    events, response_packets = _drain(server, client)
    assert any(
        event.kind == "incoming_stream_reset" and event.stream_ids == [1] for event in events
    )

    response_chunk = response_packets[0].chunks[0]
    assert isinstance(response_chunk, dcsctp.ReConfigChunk)
    response = response_chunk.parameters[0]
    assert isinstance(response, dcsctp.ReconfigurationResponseParameter)
    assert response.result == dcsctp.ReconfigurationResponseResult.SUCCESS_PERFORMED

    # 応答を受け取ったクライアントはリセット完了イベントを出す
    events, _ = _drain(client, server)
    assert any(event.kind == "streams_reset_performed" for event in events)


def test_shutdown_packets() -> None:
    """シャットダウンで SHUTDOWN / SHUTDOWN ACK / SHUTDOWN COMPLETE が交換されること。"""
    client, server, _ = _connect_pair()

    # SHUTDOWN には相手から受信済みの累積 TSN が入る (RFC 9260 Section 3.3.8)
    server.send(dcsctp.Message(stream_id=1, ppid=53, payload=b"bye"))
    _, data_packets = _drain(server, client)
    data = data_packets[0].chunks[0]
    assert isinstance(data, dcsctp.DataChunk)
    _drain(client, server)

    client.shutdown()
    _, shutdown_packets = _drain(client, server)
    shutdown = shutdown_packets[0].chunks[0]
    assert isinstance(shutdown, dcsctp.ShutdownChunk)
    assert shutdown.cumulative_tsn_ack == data.tsn

    # サーバーは SHUTDOWN ACK を返す (RFC 9260 Section 3.3.9)
    _, ack_packets = _drain(server, client)
    assert isinstance(ack_packets[0].chunks[0], dcsctp.ShutdownAckChunk)

    # クライアントは SHUTDOWN COMPLETE を返す (RFC 9260 Section 3.3.13)
    _, complete_packets = _drain(client, server)
    assert isinstance(complete_packets[0].chunks[0], dcsctp.ShutdownCompleteChunk)

    _drain(server, client)
    assert client.state() == dcsctp.SocketState.Closed
    assert server.state() == dcsctp.SocketState.Closed


def test_handover_state_and_restore() -> None:
    """接続済みソケットの状態を別のソケットへ引き継げること。"""
    client, server, _ = _connect_pair()

    # 接続直後は即時にハンドオーバーできる
    readiness = client.get_handover_readiness()
    assert isinstance(readiness, dcsctp.HandoverReadiness)
    assert readiness.is_ready()
    assert readiness.reasons() == []

    # 状態を取得すると元のソケットは同期的に閉じる
    state = client.get_handover_state_and_close()
    assert client.state() == dcsctp.SocketState.Closed
    assert state.is_connected
    assert state.my_verification_tag != 0
    assert state.peer_verification_tag != 0
    assert state.next_tsn == state.my_initial_tsn

    # 新しいソケットで復元すると Connected に戻る
    restored = dcsctp.Socket("restored")
    restored.restore_from_state(state)
    assert restored.state() == dcsctp.SocketState.Connected

    # 復元後も相手と通信でき、TSN は引き継いだ続きから使われる
    restored.send(dcsctp.Message(stream_id=1, ppid=53, payload=b"handed over"))
    _, packets = _drain(restored, server)

    data = packets[0].chunks[0]
    assert isinstance(data, dcsctp.DataChunk)
    assert data.tsn == state.next_tsn
    assert data.payload == b"handed over"
    assert server.messages_ready_count() == 1


def test_handover_readiness_with_outstanding_data() -> None:
    """未確認のデータがあるとハンドオーバーできないこと。"""
    client, _, _ = _connect_pair()

    # 相手に届かないメッセージを送って未確認データを作る
    client.send(dcsctp.Message(stream_id=1, ppid=53, payload=b"unacked"))
    _drain(client)

    readiness = client.get_handover_readiness()
    assert not readiness.is_ready()
    assert readiness.reasons() == ["retransmission_queue_outstanding_data"]

    with pytest.raises(RuntimeError, match="ready state for handover"):
        client.get_handover_state_and_close()


def test_restore_from_state_requires_closed_socket() -> None:
    """接続中ソケットへの状態復元は失敗すること。"""
    client, _, _ = _connect_pair()
    state = client.get_handover_state_and_close()

    socket = dcsctp.Socket("other")
    socket.connect()
    with pytest.raises(RuntimeError, match="not closed"):
        socket.restore_from_state(state)


def _initiate_tag(packets: list[dcsctp.Packet]) -> int:
    """INIT / INIT-ACK パケットから initiate_tag を取り出す。"""
    chunk = packets[0].chunks[0]
    if isinstance(chunk, dcsctp.InitChunk | dcsctp.InitAckChunk):
        return chunk.initiate_tag
    raise AssertionError(f"packet is not an INIT/INIT-ACK: {chunk!r}")
