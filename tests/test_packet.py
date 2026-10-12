"""SCTP パケットコーデックの低レイヤーテスト。

dcsctp (webrtc/dcsctp) の Rust テストに含まれる実パケット捕捉データを使い、
バイト列の解釈と組み立てが dcsctp と一致することを検証する。
"""

import struct

import dcsctp
import pytest

# dcsctp の src/packet/sctp_packet.rs (deserialize_simple_packet_from_capture) の捕捉データ
INIT_PACKET: bytes = bytes.fromhex(
    "1388138800000000aa019d330100005a0eddca080002000003e803e85508363780000004c0000004"
    "80080009c00fc1808200000080020024c5a86155090e6f420050634cc8d6b908dfd53e17c99cb143"
    "284eaf64682ac29780040006000100008003000680c10000"
)

# dcsctp の src/packet/sctp_packet.rs (deserialize_packet_with_two_chunks) の捕捉データ
COOKIE_ACK_SACK_PACKET: bytes = bytes.fromhex(
    "04d210e1697e3a4ec06e8b360b00000403000010aea952520002000000000000"
)


def test_crc32c_known_vectors() -> None:
    """CRC-32C が RFC 9260 Appendix B の実装と一致すること。"""
    # dcsctp の src/packet/crc32c.rs のテストと同じ検証値
    assert dcsctp.crc32c(b"") == 0x00000000
    assert dcsctp.crc32c(b"123456789") == 0xE3069283
    assert dcsctp.crc32c(b"1234") == 0xF63AF4EE
    assert dcsctp.crc32c(b"12345678") == 0x6087809A


def test_init_packet_parses_and_roundtrips() -> None:
    """捕捉した INIT パケットを共通ヘッダとチャンクまで解析できること。"""
    packet = dcsctp.Packet.parse(INIT_PACKET)

    # 共通ヘッダ (RFC 9260 Section 3.1)
    assert packet.source_port == 5000
    assert packet.destination_port == 5000
    assert packet.verification_tag == 0
    # SCTP のチェックサムはリトルエンディアンで格納されている
    assert packet.checksum == 0x339D01AA
    assert packet.has_valid_checksum()

    # INIT チャンク (RFC 9260 Section 3.3.2)
    assert len(packet.chunks) == 1
    init = packet.chunks[0]
    assert isinstance(init, dcsctp.InitChunk)
    assert init.initiate_tag == 0x0EDDCA08
    assert init.a_rwnd == 131072
    assert init.outbound_streams == 1000
    assert init.inbound_streams == 1000
    assert init.initial_tsn == 1426601527

    # パラメータ (RFC 9260 Section 3.3.2.1、RFC 5061 Section 4.2.7)
    assert isinstance(init.parameters[1], dcsctp.ForwardTsnSupportedParameter)
    supported = init.parameters[2]
    assert isinstance(supported, dcsctp.SupportedExtensionsParameter)
    assert supported.chunk_types == [192, 15, 193, 128, 130]

    # 最後のパラメータのパディングをチャンクのパディングと重ねる dcsctp の
    # 直列化規則 (RFC 9260 Section 3.2) でバイト単位に一致すること
    assert packet.to_bytes() == INIT_PACKET


def test_cookie_ack_and_sack_packet_parses() -> None:
    """1 パケットに複数チャンクが入っている場合も解析できること。"""
    packet = dcsctp.Packet.parse(COOKIE_ACK_SACK_PACKET)

    assert packet.source_port == 1234
    assert packet.destination_port == 4321
    assert packet.verification_tag == 0x697E3A4E
    assert packet.has_valid_checksum()

    assert isinstance(packet.chunks[0], dcsctp.CookieAckChunk)
    sack = packet.chunks[1]
    assert isinstance(sack, dcsctp.SackChunk)
    assert sack.cumulative_tsn_ack == 2930332242
    assert sack.a_rwnd == 131072
    assert sack.gap_ack_blocks == []
    assert sack.duplicate_tsns == []

    assert packet.to_bytes() == COOKIE_ACK_SACK_PACKET


def test_data_chunk_fixture() -> None:
    """捕捉した DATA チャンクの各フィールドとフラグを解析できること (RFC 9260 Section 3.3.1)。"""
    # dcsctp の src/packet/data_chunk.rs の捕捉データ
    chunk = dcsctp.parse_chunk(bytes.fromhex("000300145508363c000200010000003500010203"))

    assert isinstance(chunk, dcsctp.DataChunk)
    assert chunk.tsn == 0x5508363C
    assert chunk.stream_id == 2
    assert chunk.ssn == 1
    assert chunk.ppid == 0x35
    assert chunk.payload == b"\x00\x01\x02\x03"
    assert chunk.beginning
    assert chunk.end
    assert not chunk.unordered
    assert not chunk.immediate_ack


def test_sack_chunk_fixture() -> None:
    """ギャップ ACK ブロックと重複 TSN を持つ SACK を解析できること (RFC 9260 Section 3.3.4)。"""
    # dcsctp の src/packet/sack_chunk.rs の捕捉データ
    chunk = dcsctp.parse_chunk(
        bytes.fromhex("0300001c369dd00b0001ed73000200010002000600080008369dd011")
    )

    assert isinstance(chunk, dcsctp.SackChunk)
    assert chunk.cumulative_tsn_ack == 0x369DD00B
    assert chunk.a_rwnd == 0x0001ED73
    assert chunk.gap_ack_blocks == [dcsctp.GapAckBlock(2, 6), dcsctp.GapAckBlock(8, 8)]
    assert chunk.duplicate_tsns == [0x369DD011]


def test_forward_tsn_chunk_fixture() -> None:
    """FORWARD-TSN を解析できること (RFC 3758 Section 3.2)。"""
    # dcsctp の src/packet/forward_tsn_chunk.rs の捕捉データ
    chunk = dcsctp.parse_chunk(bytes.fromhex("c000000871976b2a"))

    assert isinstance(chunk, dcsctp.ForwardTsnChunk)
    assert chunk.new_cumulative_tsn == 0x71976B2A
    assert chunk.skipped_streams == []


def test_iforward_tsn_chunk_fixture() -> None:
    """I-FORWARD-TSN を解析できること (RFC 8260 Section 2.3.1)。"""
    # dcsctp の src/packet/iforward_tsn_chunk.rs の捕捉データ
    chunk = dcsctp.parse_chunk(bytes.fromhex("c2000010b87452ec0001000000000002"))

    assert isinstance(chunk, dcsctp.IForwardTsnChunk)
    assert chunk.new_cumulative_tsn == 0xB87452EC
    assert chunk.skipped_streams == [dcsctp.IForwardTsnSkippedStream(1, False, 2)]


def test_idata_chunk_beginning_uses_ppid() -> None:
    """先頭フラグメントの I-DATA は PPID を持つこと (RFC 8260 Section 2.1)。"""
    # dcsctp の src/packet/idata_chunk.rs の捕捉データ (B フラグのみ)
    chunk = dcsctp.parse_chunk(bytes.fromhex("40020015944a5dd500010000000000000000003501000000"))

    assert isinstance(chunk, dcsctp.IDataChunk)
    assert chunk.tsn == 0x944A5DD5
    assert chunk.stream_id == 1
    assert chunk.mid == 0
    assert chunk.ppid == 0x35
    assert chunk.fsn == 0
    assert chunk.beginning
    assert not chunk.end
    assert chunk.payload == b"\x01"


def test_idata_chunk_non_beginning_uses_fsn() -> None:
    """途中フラグメントの I-DATA は FSN を持つこと (RFC 8260 Section 2.1)。"""
    # dcsctp の src/packet/idata_chunk.rs の捕捉データ (E フラグのみ)
    chunk = dcsctp.parse_chunk(bytes.fromhex("40010015944a5e0a00030000000000010000000801000000"))

    assert isinstance(chunk, dcsctp.IDataChunk)
    assert chunk.ppid == 0
    assert chunk.fsn == 8
    assert chunk.mid == 1
    assert not chunk.beginning
    assert chunk.end


def test_reconfig_chunk_fixture() -> None:
    """RE-CONFIG の Outgoing SSN Reset Request を解析できること (RFC 6525 Section 4.1)。"""
    # dcsctp の src/packet/re_config_chunk.rs の捕捉データ
    chunk = dcsctp.parse_chunk(bytes.fromhex("82000016000d00128755d82371976a9e8755d83200060000"))

    assert isinstance(chunk, dcsctp.ReConfigChunk)
    parameter = chunk.parameters[0]
    assert isinstance(parameter, dcsctp.OutgoingSsnResetRequestParameter)
    assert parameter.request_sequence_number == 0x8755D823
    assert parameter.response_sequence_number == 0x71976A9E
    assert parameter.sender_last_assigned_tsn == 0x8755D832
    assert parameter.stream_ids == [6]


def test_abort_chunk_fixture() -> None:
    """ABORT の User-Initiated Abort エラー原因を解析できること (RFC 9260 Section 3.3.7)。"""
    # dcsctp の src/packet/abort_chunk.rs の捕捉データ
    chunk = dcsctp.parse_chunk(bytes.fromhex("06000008000c0004"))

    assert isinstance(chunk, dcsctp.AbortChunk)
    assert not chunk.tag_reflected
    assert len(chunk.error_causes) == 1
    cause = chunk.error_causes[0]
    assert isinstance(cause, dcsctp.UserInitiatedAbortErrorCause)
    assert cause.cause_code == dcsctp.ErrorCauseCode.USER_INITIATED_ABORT
    assert cause.reason == b""


def test_error_chunk_fixture() -> None:
    """ERROR の Unrecognized Chunk Type エラー原因を解析できること (RFC 9260 Section 3.3.10)。"""
    # dcsctp の src/packet/error_chunk.rs の捕捉データ
    chunk = dcsctp.parse_chunk(bytes.fromhex("0900000c0006000849000004"))

    assert isinstance(chunk, dcsctp.ErrorChunk)
    cause = chunk.error_causes[0]
    assert isinstance(cause, dcsctp.UnrecognizedChunkErrorCause)
    # 問題となったチャンク全体 (ヘッダを含む) がそのまま入っている
    assert cause.chunk == bytes.fromhex("49000004")


def test_heartbeat_chunk_fixture() -> None:
    """HEARTBEAT の Heartbeat Info パラメータを解析できること (RFC 9260 Section 3.3.5)。"""
    # dcsctp の src/packet/heartbeat_request_chunk.rs の捕捉データ
    chunk = dcsctp.parse_chunk(
        bytes.fromhex(
            "0400002c00010028ad2436603726070000000000000000007b10000001000000000000000000000000000000"
        )
    )

    assert isinstance(chunk, dcsctp.HeartbeatChunk)
    parameter = chunk.parameters[0]
    assert isinstance(parameter, dcsctp.HeartbeatInfoParameter)
    assert parameter.info == bytes.fromhex(
        "ad2436603726070000000000000000007b10000001000000000000000000000000000000"
    )


@pytest.mark.parametrize(
    "chunk",
    [
        dcsctp.DataChunk(tsn=1, stream_id=2, ssn=3, ppid=53, payload=b"hello"),
        dcsctp.DataChunk(
            tsn=4, stream_id=5, ssn=6, ppid=7, payload=b"", unordered=True, immediate_ack=True
        ),
        dcsctp.IDataChunk(tsn=1, stream_id=2, mid=3, ppid=53, payload=b"data"),
        dcsctp.IDataChunk(tsn=4, stream_id=5, mid=6, fsn=7, payload=b"tail", beginning=False),
        dcsctp.InitChunk(
            initiate_tag=1,
            a_rwnd=2,
            outbound_streams=3,
            inbound_streams=4,
            initial_tsn=5,
            parameters=[dcsctp.ForwardTsnSupportedParameter()],
        ),
        dcsctp.InitAckChunk(
            initiate_tag=6,
            a_rwnd=7,
            outbound_streams=8,
            inbound_streams=9,
            initial_tsn=10,
            parameters=[dcsctp.StateCookieParameter(b"cookie")],
        ),
        dcsctp.SackChunk(
            cumulative_tsn_ack=1,
            a_rwnd=2,
            gap_ack_blocks=[dcsctp.GapAckBlock(3, 4)],
            duplicate_tsns=[5, 6],
        ),
        dcsctp.HeartbeatChunk(parameters=[dcsctp.HeartbeatInfoParameter(b"info")]),
        dcsctp.HeartbeatAckChunk(parameters=[dcsctp.HeartbeatInfoParameter(b"info")]),
        dcsctp.AbortChunk(
            error_causes=[dcsctp.UserInitiatedAbortErrorCause(b"bye")], tag_reflected=True
        ),
        dcsctp.ShutdownChunk(cumulative_tsn_ack=123),
        dcsctp.ShutdownAckChunk(),
        dcsctp.ErrorChunk(error_causes=[dcsctp.NoUserDataErrorCause(tsn=1)]),
        dcsctp.CookieEchoChunk(b"cookie"),
        dcsctp.CookieAckChunk(),
        dcsctp.ShutdownCompleteChunk(tag_reflected=True),
        dcsctp.ForwardTsnChunk(
            new_cumulative_tsn=1,
            skipped_streams=[dcsctp.ForwardTsnSkippedStream(2, 3)],
        ),
        dcsctp.IForwardTsnChunk(
            new_cumulative_tsn=1,
            skipped_streams=[dcsctp.IForwardTsnSkippedStream(2, True, 3)],
        ),
        dcsctp.ReConfigChunk(
            parameters=[
                dcsctp.IncomingSsnResetRequestParameter(request_sequence_number=1, stream_ids=[2])
            ]
        ),
        dcsctp.UnknownChunk(0x42, b"\x01\x02\x03\x04"),
    ],
    ids=[
        "data",
        "data-unordered-immediate-ack",
        "idata-beginning",
        "idata-continuation",
        "init",
        "init-ack",
        "sack",
        "heartbeat",
        "heartbeat-ack",
        "abort",
        "shutdown",
        "shutdown-ack",
        "error",
        "cookie-echo",
        "cookie-ack",
        "shutdown-complete",
        "forward-tsn",
        "i-forward-tsn",
        "re-config",
        "unknown",
    ],
)
def test_chunk_roundtrip(chunk: dcsctp.Chunk) -> None:
    """組み立てた全種別のチャンクが解析後に同じバイト列へ戻ること。"""
    parsed = dcsctp.parse_chunk(chunk.to_bytes())

    assert type(parsed) is type(chunk)
    assert parsed.flags == chunk.flags
    assert parsed.to_bytes() == chunk.to_bytes()


def test_packet_roundtrip_with_multiple_chunks() -> None:
    """複数チャンクを持つパケットを組み立てて解析できること。"""
    packet = dcsctp.Packet(
        source_port=5000,
        destination_port=5001,
        verification_tag=0x12345678,
        chunks=[
            dcsctp.DataChunk(tsn=1, stream_id=0, ssn=0, ppid=53, payload=b"a"),
            dcsctp.DataChunk(tsn=2, stream_id=0, ssn=0, ppid=53, payload=b"b"),
            dcsctp.SackChunk(cumulative_tsn_ack=2, a_rwnd=1024),
        ],
    )

    data = packet.to_bytes()
    parsed = dcsctp.Packet.parse(data)

    assert parsed.source_port == 5000
    assert parsed.destination_port == 5001
    assert parsed.verification_tag == 0x12345678
    assert parsed.has_valid_checksum()
    assert [type(chunk) for chunk in parsed.chunks] == [
        dcsctp.DataChunk,
        dcsctp.DataChunk,
        dcsctp.SackChunk,
    ]
    assert parsed.to_bytes() == data


def test_packet_checksum_can_be_overridden() -> None:
    """チェックサムを 0 にした壊れたパケットを意図的に組み立てられること。"""
    packet = dcsctp.Packet(5000, 5000, 42, [dcsctp.CookieAckChunk()])

    data = packet.to_bytes(checksum=0)
    parsed = dcsctp.Packet.parse(data)

    assert data[8:12] == b"\x00\x00\x00\x00"
    assert parsed.checksum == 0
    assert not parsed.has_valid_checksum()
    # 正しいチェックサムを計算すれば同じパケットが得られる
    assert (
        packet.to_bytes() == data[:8] + packet.compute_checksum().to_bytes(4, "little") + data[12:]
    )


def test_missing_mandatory_parameter_error_cause_roundtrip() -> None:
    """Missing Mandatory Parameter エラー原因のパラメータ種別一覧を保持できること。"""
    cause = dcsctp.MissingMandatoryParameterErrorCause([7, 13])

    parsed = dcsctp.parse_error_causes(cause.to_bytes())[0]

    assert isinstance(parsed, dcsctp.MissingMandatoryParameterErrorCause)
    assert parsed.missing_parameters == [7, 13]


def test_cookie_received_while_shutting_down_error_cause_roundtrip() -> None:
    """値を持たないエラー原因もラウンドトリップできること。"""
    cause = dcsctp.CookieReceivedWhileShuttingDownErrorCause()

    parsed = dcsctp.parse_error_causes(cause.to_bytes())[0]

    assert isinstance(parsed, dcsctp.CookieReceivedWhileShuttingDownErrorCause)
    assert parsed.value == b""


def test_reconfiguration_response_parameter_roundtrip() -> None:
    """RE-CONFIG 応答の結果コードを保持できること (RFC 6525 Section 4.4)。"""
    parameter = dcsctp.ReconfigurationResponseParameter(
        response_sequence_number=99,
        result=dcsctp.ReconfigurationResponseResult.SUCCESS_PERFORMED,
        sender_next_tsn=100,
        receiver_next_tsn=200,
    )

    parsed = dcsctp.parse_parameters(parameter.to_bytes())[0]

    assert isinstance(parsed, dcsctp.ReconfigurationResponseParameter)
    assert parsed.response_sequence_number == 99
    assert parsed.result == dcsctp.ReconfigurationResponseResult.SUCCESS_PERFORMED
    assert parsed.sender_next_tsn == 100
    assert parsed.receiver_next_tsn == 200


def test_zero_checksum_acceptable_parameter_roundtrip() -> None:
    """Zero Checksum Acceptable パラメータを解析できること (RFC 9653 Section 4)。"""
    parameter = dcsctp.ZeroChecksumAcceptableParameter(1)

    parsed = dcsctp.parse_parameters(parameter.to_bytes())[0]

    assert isinstance(parsed, dcsctp.ZeroChecksumAcceptableParameter)
    assert parsed.error_detection_method == 1


@pytest.mark.parametrize(
    ("data", "message"),
    [
        (b"\x00" * 8, "shorter than the common header"),
        (struct.pack("!HHII", 1, 1, 0, 0)[:11], "shorter than the common header"),
        (struct.pack("!HHII", 1, 1, 0, 0) + b"\x00\x00\x00", "chunk"),
        (struct.pack("!HHII", 1, 1, 0, 0) + b"\x03\x00\x00\x02", "invalid length"),
        (struct.pack("!HHII", 1, 1, 0, 0) + b"\x03\x00\x00\x20", "exceeds available data"),
    ],
    ids=[
        "empty",
        "truncated-common-header",
        "truncated-chunk-header",
        "chunk-length-too-small",
        "chunk-length-beyond-data",
    ],
)
def test_malformed_packet_raises(data: bytes, message: str) -> None:
    """壊れたパケットは PacketParseError になること。"""
    with pytest.raises(dcsctp.PacketParseError, match=message):
        dcsctp.Packet.parse(data)


@pytest.mark.parametrize(
    ("data", "message"),
    [
        (bytes.fromhex("00000008") + b"\x00" * 4, "too short"),
        (bytes.fromhex("03000010") + struct.pack("!IIHH", 0, 0, 1, 0), "length mismatch"),
        (bytes.fromhex("07000006") + b"\x00\x00", "must be 4 bytes"),
        (bytes.fromhex("0b000008") + b"\x01\x02\x03\x04", "must be empty"),
        (bytes.fromhex("8200000c") + bytes.fromhex("00100008") + b"\x00" * 4, "invalid length"),
    ],
    ids=[
        "data-too-short",
        "sack-count-mismatch",
        "shutdown-wrong-size",
        "cookie-ack-not-empty",
        "re-config-response-wrong-size",
    ],
)
def test_malformed_chunk_raises(data: bytes, message: str) -> None:
    """壊れたチャンクは PacketParseError になること。"""
    with pytest.raises(dcsctp.PacketParseError, match=message):
        dcsctp.parse_chunk(data)


def test_malformed_error_cause_raises() -> None:
    """数が一致しない Missing Mandatory Parameter は PacketParseError になること。"""
    data = struct.pack("!HHI", 2, 8, 3) + struct.pack("!H", 7)

    with pytest.raises(dcsctp.PacketParseError, match="invalid length"):
        dcsctp.parse_error_causes(data)


def test_unknown_parameter_is_preserved() -> None:
    """未知のパラメータは種別と生の値を保持すること。"""
    data = struct.pack("!HH", 0x8002, 8) + b"\x01\x02\x03\x04"

    parsed = dcsctp.parse_parameters(data)[0]

    assert type(parsed) is dcsctp.Parameter
    assert parsed.parameter_type == 0x8002
    assert parsed.value == b"\x01\x02\x03\x04"


def test_unknown_chunk_is_preserved() -> None:
    """未知のチャンクは種別とフラグと生の値を保持すること。"""
    # dcsctp の src/packet/chunk.rs のテストデータ
    chunk = dcsctp.parse_chunk(bytes.fromhex("4200000801020304"))

    assert isinstance(chunk, dcsctp.UnknownChunk)
    assert chunk.chunk_type == 0x42
    assert chunk.flags == 0
    assert chunk.value == b"\x01\x02\x03\x04"
    assert chunk.to_bytes() == bytes.fromhex("4200000801020304")
