"""SCTP パケットとチャンクを低レイヤーで解析・組み立てするコーデック。

`Socket` は SCTP パケットを生バイト列として送受信するため、このモジュールを使うと
チャンクやパラメータの単位まで分解して動作確認できる。また、テスト用に任意の
パケットを組み立てて `Socket.handle_input()` へ注入することもできる。

実装は dcsctp (webrtc/dcsctp) の `src/packet` の解釈に合わせている。参照仕様:

- RFC 9260: Stream Control Transmission Protocol
- RFC 3758: Partial Reliability Extension (FORWARD-TSN)
- RFC 5061: SCTP Dynamic Address Reconfiguration (Supported Extensions)
- RFC 6525: SCTP Stream Reconfiguration (RE-CONFIG)
- RFC 8260: SCTP Stream Schedulers and User Message Interleaving (I-DATA/I-FORWARD-TSN)
- RFC 9653: Zero Checksum for SCTP

仕様および dcsctp の実装は将来変更される可能性があるため、解析結果の解釈を
テストで固定する場合は注意すること。
"""

from __future__ import annotations

import struct
from collections.abc import Iterable, Sequence
from enum import IntEnum
from typing import ClassVar, NamedTuple

__all__ = [
    "AbortChunk",
    "Chunk",
    "ChunkType",
    "CookieAckChunk",
    "CookieEchoChunk",
    "CookieReceivedWhileShuttingDownErrorCause",
    "DataChunk",
    "ErrorCause",
    "ErrorCauseCode",
    "ErrorChunk",
    "ForwardTsnChunk",
    "ForwardTsnSkippedStream",
    "ForwardTsnSupportedParameter",
    "GapAckBlock",
    "HeartbeatAckChunk",
    "HeartbeatChunk",
    "HeartbeatInfoParameter",
    "IDataChunk",
    "IForwardTsnChunk",
    "IForwardTsnSkippedStream",
    "IncomingSsnResetRequestParameter",
    "InitAckChunk",
    "InitChunk",
    "MissingMandatoryParameterErrorCause",
    "NoUserDataErrorCause",
    "OutgoingSsnResetRequestParameter",
    "Packet",
    "PacketParseError",
    "Parameter",
    "ParameterType",
    "ProtocolViolationErrorCause",
    "ReConfigChunk",
    "ReconfigurationResponseParameter",
    "ReconfigurationResponseResult",
    "SackChunk",
    "ShutdownAckChunk",
    "ShutdownChunk",
    "ShutdownCompleteChunk",
    "StateCookieParameter",
    "SupportedExtensionsParameter",
    "UnknownChunk",
    "UnrecognizedChunkErrorCause",
    "UserInitiatedAbortErrorCause",
    "ZeroChecksumAcceptableParameter",
    "crc32c",
    "parse_chunk",
    "parse_chunks",
    "parse_error_causes",
    "parse_parameters",
]

# チャンク・パラメータ・エラー原因は共通の Type-Length-Value ヘッダを持つ
# (RFC 9260 Section 3.2)
_TLV_HEADER_SIZE = 4
# SCTP パケットの共通ヘッダ長 (RFC 9260 Section 3.1)
_COMMON_HEADER_SIZE = 12


class PacketParseError(ValueError):
    """SCTP パケット・チャンク・パラメータの解析に失敗したことを表す。"""


# CRC-32C (Castagnoli) の反転多項式。通常の CRC-32 (ISO 3309) とは異なる
# (RFC 9260 Appendix B)
_CRC32C_POLYNOMIAL = 0x82F63B78


def _create_crc32c_table() -> tuple[int, ...]:
    """CRC-32C のバイト単位計算に使うテーブルを生成する。"""
    table: list[int] = []
    for index in range(256):
        remainder = index
        for _ in range(8):
            if remainder & 1:
                remainder = (remainder >> 1) ^ _CRC32C_POLYNOMIAL
            else:
                remainder >>= 1
        table.append(remainder)
    return tuple(table)


_CRC32C_TABLE = _create_crc32c_table()


def crc32c(data: bytes | bytearray) -> int:
    """CRC-32C を計算して符号なし 32 bit 整数で返す (RFC 9260 Appendix B)。"""
    crc = 0xFFFFFFFF
    for byte in data:
        crc = (crc >> 8) ^ _CRC32C_TABLE[(crc ^ byte) & 0xFF]
    return crc ^ 0xFFFFFFFF


def _round_up_to_four(size: int) -> int:
    """SCTP の 4 バイト境界に切り上げる。"""
    return (size + 3) & ~3


def _padding(size: int) -> bytes:
    """4 バイト境界までのパディングを返す。"""
    return bytes(-size % 4)


def _check_tlv_length(length: int, what: str) -> None:
    """TLV の長さフィールドが表現可能な範囲かを検査する。"""
    if length > 0xFFFF:
        raise ValueError(f"{what} is too large to serialize: {length} bytes")


class ChunkType(IntEnum):
    """SCTP チャンクの種別 (RFC 9260 Section 3.2、RFC 8260、RFC 6525)。"""

    DATA = 0
    INIT = 1
    INIT_ACK = 2
    SACK = 3
    HEARTBEAT = 4
    HEARTBEAT_ACK = 5
    ABORT = 6
    SHUTDOWN = 7
    SHUTDOWN_ACK = 8
    ERROR = 9
    COOKIE_ECHO = 10
    COOKIE_ACK = 11
    SHUTDOWN_COMPLETE = 14
    I_DATA = 64
    RE_CONFIG = 130
    FORWARD_TSN = 192
    I_FORWARD_TSN = 194


class ParameterType(IntEnum):
    """INIT/INIT-ACK/HEARTBEAT/RE-CONFIG に含まれるパラメータの種別。"""

    HEARTBEAT_INFO = 1
    STATE_COOKIE = 7
    OUTGOING_SSN_RESET_REQUEST = 13
    INCOMING_SSN_RESET_REQUEST = 14
    SSN_TSN_RESET_REQUEST = 15
    RECONFIGURATION_RESPONSE = 16
    ADD_OUTGOING_STREAMS_REQUEST = 17
    ADD_INCOMING_STREAMS_REQUEST = 18
    ZERO_CHECKSUM_ACCEPTABLE = 0x8001
    SUPPORTED_EXTENSIONS = 0x8008
    FORWARD_TSN_SUPPORTED = 0xC000


class ErrorCauseCode(IntEnum):
    """ERROR/ABORT チャンクに含まれるエラー原因コード (RFC 9260 Section 3.3.10.1)。"""

    INVALID_STREAM_IDENTIFIER = 1
    MISSING_MANDATORY_PARAMETER = 2
    STALE_COOKIE = 3
    OUT_OF_RESOURCE = 4
    UNRESOLVABLE_ADDRESS = 5
    UNRECOGNIZED_CHUNK_TYPE = 6
    INVALID_MANDATORY_PARAMETER = 7
    UNRECOGNIZED_PARAMETERS = 8
    NO_USER_DATA = 9
    COOKIE_RECEIVED_WHILE_SHUTTING_DOWN = 10
    RESTART_OF_AN_ASSOCIATION_WITH_NEW_ADDRESSES = 11
    USER_INITIATED_ABORT = 12
    PROTOCOL_VIOLATION = 13


class ReconfigurationResponseResult(IntEnum):
    """RE-CONFIG 応答の結果コード (RFC 6525 Section 4.4)。"""

    SUCCESS_NOTHING_TO_DO = 0
    SUCCESS_PERFORMED = 1
    DENIED = 2
    ERROR_WRONG_SSN = 3
    ERROR_REQUEST_ALREADY_IN_PROGRESS = 4
    ERROR_BAD_SEQUENCE_NUMBER = 5
    IN_PROGRESS = 6


class Chunk:
    """SCTP チャンクの基底クラス。

    種別を判別できなかったチャンクは `UnknownChunk` ではなくこのクラスでそのまま
    表現する。任意のチャンクを組み立てたい場合もこのクラスを直接使う。
    """

    # サブクラスが持つチャンク種別。基底クラスでは未定義
    _CHUNK_TYPE: ClassVar[ChunkType | None] = None

    def __init__(self, chunk_type: int, value: bytes = b"", flags: int = 0) -> None:
        self.chunk_type = chunk_type
        self.value = bytes(value)
        self.flags = flags & 0xFF

    @classmethod
    def _parse_value(cls, flags: int, value: bytes) -> Chunk:
        """チャンク値を解析してインスタンスを返す。サブクラスで実装する。"""
        raise NotImplementedError

    def to_bytes(self) -> bytes:
        """チャンクヘッダ + 値 + パディングへ直列化する。"""
        length = _TLV_HEADER_SIZE + len(self.value)
        _check_tlv_length(length, "chunk")
        header = struct.pack("!BBH", self.chunk_type, self.flags, length)
        return header + self.value + _padding(length)

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(chunk_type={self.chunk_type}, "
            f"flags=0x{self.flags:02x}, value={self.value!r})"
        )


class UnknownChunk(Chunk):
    """dcsctp が扱わない、または未知の種別のチャンク (RFC 9260 Section 3.2)。

    未知のチャンクを注入するような試験のために、種別を明示して組み立てられる。
    """

    def __init__(self, chunk_type: int, value: bytes = b"", flags: int = 0) -> None:
        super().__init__(chunk_type, value, flags)


class DataChunk(Chunk):
    """Payload Data (DATA) チャンク (RFC 9260 Section 3.3.1)。

    フラグバイトのビット割り当ては E (bit 0)、B (bit 1)、U (bit 2)、I (bit 3)。
    """

    _CHUNK_TYPE: ClassVar[ChunkType] = ChunkType.DATA

    FLAG_END = 0x01
    FLAG_BEGINNING = 0x02
    FLAG_UNORDERED = 0x04
    FLAG_IMMEDIATE_ACK = 0x08

    def __init__(
        self,
        tsn: int,
        stream_id: int,
        ssn: int,
        ppid: int,
        payload: bytes = b"",
        *,
        unordered: bool = False,
        beginning: bool = True,
        end: bool = True,
        immediate_ack: bool = False,
    ) -> None:
        flags = 0
        if end:
            flags |= self.FLAG_END
        if beginning:
            flags |= self.FLAG_BEGINNING
        if unordered:
            flags |= self.FLAG_UNORDERED
        if immediate_ack:
            flags |= self.FLAG_IMMEDIATE_ACK
        value = struct.pack("!IHHI", tsn, stream_id, ssn, ppid) + bytes(payload)
        super().__init__(self._CHUNK_TYPE, value, flags)
        self.tsn = tsn
        self.stream_id = stream_id
        self.ssn = ssn
        self.ppid = ppid
        self.payload = bytes(payload)
        self.unordered = unordered
        self.beginning = beginning
        self.end = end
        self.immediate_ack = immediate_ack

    @classmethod
    def _parse_value(cls, flags: int, value: bytes) -> DataChunk:
        if len(value) < 12:
            raise PacketParseError(f"DATA chunk value is too short: {len(value)} bytes")
        tsn, stream_id, ssn, ppid = struct.unpack_from("!IHHI", value)
        return cls(
            tsn=tsn,
            stream_id=stream_id,
            ssn=ssn,
            ppid=ppid,
            payload=value[12:],
            unordered=bool(flags & cls.FLAG_UNORDERED),
            beginning=bool(flags & cls.FLAG_BEGINNING),
            end=bool(flags & cls.FLAG_END),
            immediate_ack=bool(flags & cls.FLAG_IMMEDIATE_ACK),
        )


class IDataChunk(Chunk):
    """Payload Data supporting Interleaving (I-DATA) チャンク (RFC 8260 Section 2.1)。

    B ビットが立っている場合は PPID を、立っていない場合はフラグメントシーケンス
    番号 (FSN) を持つ。dcsctp と同様に、使わない側のフィールドは 0 として扱う。
    """

    _CHUNK_TYPE: ClassVar[ChunkType] = ChunkType.I_DATA

    FLAG_END = 0x01
    FLAG_BEGINNING = 0x02
    FLAG_UNORDERED = 0x04
    FLAG_IMMEDIATE_ACK = 0x08

    def __init__(
        self,
        tsn: int,
        stream_id: int,
        mid: int,
        payload: bytes = b"",
        *,
        ppid: int = 0,
        fsn: int = 0,
        unordered: bool = False,
        beginning: bool = True,
        end: bool = True,
        immediate_ack: bool = False,
    ) -> None:
        flags = 0
        if end:
            flags |= self.FLAG_END
        if beginning:
            flags |= self.FLAG_BEGINNING
        if unordered:
            flags |= self.FLAG_UNORDERED
        if immediate_ack:
            flags |= self.FLAG_IMMEDIATE_ACK
        ppid_or_fsn = ppid if beginning else fsn
        value = struct.pack("!IHHII", tsn, stream_id, 0, mid, ppid_or_fsn) + bytes(payload)
        super().__init__(self._CHUNK_TYPE, value, flags)
        self.tsn = tsn
        self.stream_id = stream_id
        self.mid = mid
        self.ppid = ppid
        self.fsn = fsn
        self.payload = bytes(payload)
        self.unordered = unordered
        self.beginning = beginning
        self.end = end
        self.immediate_ack = immediate_ack

    @classmethod
    def _parse_value(cls, flags: int, value: bytes) -> IDataChunk:
        if len(value) < 16:
            raise PacketParseError(f"I-DATA chunk value is too short: {len(value)} bytes")
        tsn, stream_id, _reserved, mid, ppid_or_fsn = struct.unpack_from("!IHHII", value)
        beginning = bool(flags & cls.FLAG_BEGINNING)
        return cls(
            tsn=tsn,
            stream_id=stream_id,
            mid=mid,
            payload=value[16:],
            ppid=ppid_or_fsn if beginning else 0,
            fsn=ppid_or_fsn if not beginning else 0,
            unordered=bool(flags & cls.FLAG_UNORDERED),
            beginning=beginning,
            end=bool(flags & cls.FLAG_END),
            immediate_ack=bool(flags & cls.FLAG_IMMEDIATE_ACK),
        )


class InitChunk(Chunk):
    """Initiation (INIT) チャンク (RFC 9260 Section 3.3.2)。"""

    _CHUNK_TYPE: ClassVar[ChunkType] = ChunkType.INIT

    def __init__(
        self,
        initiate_tag: int,
        a_rwnd: int,
        outbound_streams: int,
        inbound_streams: int,
        initial_tsn: int,
        parameters: Sequence[Parameter] = (),
    ) -> None:
        value = struct.pack(
            "!IIHHI", initiate_tag, a_rwnd, outbound_streams, inbound_streams, initial_tsn
        ) + _serialize_parameters(parameters)
        super().__init__(self._CHUNK_TYPE, value)
        self.initiate_tag = initiate_tag
        self.a_rwnd = a_rwnd
        self.outbound_streams = outbound_streams
        self.inbound_streams = inbound_streams
        self.initial_tsn = initial_tsn
        self.parameters = list(parameters)

    @classmethod
    def _parse_value(cls, flags: int, value: bytes) -> InitChunk:
        if len(value) < 16:
            raise PacketParseError(f"INIT chunk value is too short: {len(value)} bytes")
        initiate_tag, a_rwnd, outbound_streams, inbound_streams, initial_tsn = struct.unpack_from(
            "!IIHHI", value
        )
        return cls(
            initiate_tag=initiate_tag,
            a_rwnd=a_rwnd,
            outbound_streams=outbound_streams,
            inbound_streams=inbound_streams,
            initial_tsn=initial_tsn,
            parameters=parse_parameters(value[16:]),
        )


class InitAckChunk(InitChunk):
    """Initiation Acknowledgement (INIT ACK) チャンク (RFC 9260 Section 3.3.3)。"""

    _CHUNK_TYPE: ClassVar[ChunkType] = ChunkType.INIT_ACK


class GapAckBlock(NamedTuple):
    """SACK のギャップ ACK ブロック (RFC 9260 Section 3.3.4)。"""

    start: int
    end: int


class SackChunk(Chunk):
    """Selective Acknowledgement (SACK) チャンク (RFC 9260 Section 3.3.4)。"""

    _CHUNK_TYPE: ClassVar[ChunkType] = ChunkType.SACK

    def __init__(
        self,
        cumulative_tsn_ack: int,
        a_rwnd: int,
        gap_ack_blocks: Iterable[GapAckBlock] = (),
        duplicate_tsns: Iterable[int] = (),
    ) -> None:
        blocks = list(gap_ack_blocks)
        duplicates = list(duplicate_tsns)
        value = struct.pack("!IIHH", cumulative_tsn_ack, a_rwnd, len(blocks), len(duplicates))
        for block in blocks:
            value += struct.pack("!HH", block.start, block.end)
        for tsn in duplicates:
            value += struct.pack("!I", tsn)
        super().__init__(self._CHUNK_TYPE, value)
        self.cumulative_tsn_ack = cumulative_tsn_ack
        self.a_rwnd = a_rwnd
        self.gap_ack_blocks = blocks
        self.duplicate_tsns = duplicates

    @classmethod
    def _parse_value(cls, flags: int, value: bytes) -> SackChunk:
        if len(value) < 12:
            raise PacketParseError(f"SACK chunk value is too short: {len(value)} bytes")
        cumulative_tsn_ack, a_rwnd, gap_count, duplicate_count = struct.unpack_from("!IIHH", value)
        expected_length = 12 + gap_count * 4 + duplicate_count * 4
        if len(value) != expected_length:
            raise PacketParseError(
                f"SACK chunk value length mismatch: expected {expected_length} bytes "
                f"but got {len(value)}"
            )
        blocks: list[GapAckBlock] = []
        offset = 12
        for _ in range(gap_count):
            start, end = struct.unpack_from("!HH", value, offset)
            blocks.append(GapAckBlock(start, end))
            offset += 4
        duplicates: list[int] = []
        for _ in range(duplicate_count):
            (tsn,) = struct.unpack_from("!I", value, offset)
            duplicates.append(tsn)
            offset += 4
        return cls(
            cumulative_tsn_ack=cumulative_tsn_ack,
            a_rwnd=a_rwnd,
            gap_ack_blocks=blocks,
            duplicate_tsns=duplicates,
        )


class HeartbeatChunk(Chunk):
    """Heartbeat Request (HEARTBEAT) チャンク (RFC 9260 Section 3.3.5)。"""

    _CHUNK_TYPE: ClassVar[ChunkType] = ChunkType.HEARTBEAT

    def __init__(self, parameters: Sequence[Parameter]) -> None:
        super().__init__(self._CHUNK_TYPE, _serialize_parameters(parameters))
        self.parameters = list(parameters)

    @classmethod
    def _parse_value(cls, flags: int, value: bytes) -> HeartbeatChunk:
        return cls(parameters=parse_parameters(value))


class HeartbeatAckChunk(HeartbeatChunk):
    """Heartbeat Acknowledgement (HEARTBEAT ACK) チャンク (RFC 9260 Section 3.3.6)。"""

    _CHUNK_TYPE: ClassVar[ChunkType] = ChunkType.HEARTBEAT_ACK


class AbortChunk(Chunk):
    """Abort (ABORT) チャンク (RFC 9260 Section 3.3.7)。

    フラグバイトの T ビットは検証タグを反射したことを表す。
    """

    _CHUNK_TYPE: ClassVar[ChunkType] = ChunkType.ABORT

    FLAG_TAG_REFLECTED = 0x01

    def __init__(
        self, error_causes: Sequence[ErrorCause] = (), *, tag_reflected: bool = False
    ) -> None:
        flags = self.FLAG_TAG_REFLECTED if tag_reflected else 0
        super().__init__(self._CHUNK_TYPE, _serialize_error_causes(error_causes), flags)
        self.error_causes = list(error_causes)
        self.tag_reflected = tag_reflected

    @classmethod
    def _parse_value(cls, flags: int, value: bytes) -> AbortChunk:
        return cls(
            error_causes=parse_error_causes(value),
            tag_reflected=bool(flags & cls.FLAG_TAG_REFLECTED),
        )


class ShutdownChunk(Chunk):
    """Shutdown (SHUTDOWN) チャンク (RFC 9260 Section 3.3.8)。"""

    _CHUNK_TYPE: ClassVar[ChunkType] = ChunkType.SHUTDOWN

    def __init__(self, cumulative_tsn_ack: int) -> None:
        super().__init__(self._CHUNK_TYPE, struct.pack("!I", cumulative_tsn_ack))
        self.cumulative_tsn_ack = cumulative_tsn_ack

    @classmethod
    def _parse_value(cls, flags: int, value: bytes) -> ShutdownChunk:
        if len(value) != 4:
            raise PacketParseError(f"SHUTDOWN chunk value must be 4 bytes but got {len(value)}")
        (cumulative_tsn_ack,) = struct.unpack("!I", value)
        return cls(cumulative_tsn_ack)


class ShutdownAckChunk(Chunk):
    """Shutdown Acknowledgement (SHUTDOWN ACK) チャンク (RFC 9260 Section 3.3.9)。"""

    _CHUNK_TYPE: ClassVar[ChunkType] = ChunkType.SHUTDOWN_ACK

    def __init__(self) -> None:
        super().__init__(self._CHUNK_TYPE)

    @classmethod
    def _parse_value(cls, flags: int, value: bytes) -> ShutdownAckChunk:
        if value:
            raise PacketParseError(f"SHUTDOWN ACK chunk value must be empty but got {len(value)}")
        return cls()


class ErrorChunk(Chunk):
    """Operation Error (ERROR) チャンク (RFC 9260 Section 3.3.10)。"""

    _CHUNK_TYPE: ClassVar[ChunkType] = ChunkType.ERROR

    def __init__(self, error_causes: Sequence[ErrorCause]) -> None:
        if not error_causes:
            raise ValueError("ERROR chunk requires at least one error cause")
        super().__init__(self._CHUNK_TYPE, _serialize_error_causes(error_causes))
        self.error_causes = list(error_causes)

    @classmethod
    def _parse_value(cls, flags: int, value: bytes) -> ErrorChunk:
        error_causes = parse_error_causes(value)
        if not error_causes:
            raise PacketParseError("ERROR chunk requires at least one error cause")
        return cls(error_causes)


class CookieEchoChunk(Chunk):
    """State Cookie (COOKIE ECHO) チャンク (RFC 9260 Section 3.3.11)。"""

    _CHUNK_TYPE: ClassVar[ChunkType] = ChunkType.COOKIE_ECHO

    def __init__(self, cookie: bytes) -> None:
        if not cookie:
            raise ValueError("COOKIE ECHO chunk requires a non-empty cookie")
        super().__init__(self._CHUNK_TYPE, cookie)
        self.cookie = bytes(cookie)

    @classmethod
    def _parse_value(cls, flags: int, value: bytes) -> CookieEchoChunk:
        if not value:
            raise PacketParseError("COOKIE ECHO chunk requires a non-empty cookie")
        return cls(value)


class CookieAckChunk(Chunk):
    """Cookie Acknowledgement (COOKIE ACK) チャンク (RFC 9260 Section 3.3.12)。"""

    _CHUNK_TYPE: ClassVar[ChunkType] = ChunkType.COOKIE_ACK

    def __init__(self) -> None:
        super().__init__(self._CHUNK_TYPE)

    @classmethod
    def _parse_value(cls, flags: int, value: bytes) -> CookieAckChunk:
        if value:
            raise PacketParseError(f"COOKIE ACK chunk value must be empty but got {len(value)}")
        return cls()


class ShutdownCompleteChunk(Chunk):
    """Shutdown Complete (SHUTDOWN COMPLETE) チャンク (RFC 9260 Section 3.3.13)。"""

    _CHUNK_TYPE: ClassVar[ChunkType] = ChunkType.SHUTDOWN_COMPLETE

    FLAG_TAG_REFLECTED = 0x01

    def __init__(self, *, tag_reflected: bool = False) -> None:
        flags = self.FLAG_TAG_REFLECTED if tag_reflected else 0
        super().__init__(self._CHUNK_TYPE, flags=flags)
        self.tag_reflected = tag_reflected

    @classmethod
    def _parse_value(cls, flags: int, value: bytes) -> ShutdownCompleteChunk:
        if value:
            raise PacketParseError(f"SHUTDOWN COMPLETE value must be empty but got {len(value)}")
        return cls(tag_reflected=bool(flags & cls.FLAG_TAG_REFLECTED))


class ForwardTsnSkippedStream(NamedTuple):
    """FORWARD-TSN がスキップしたストリームと SSN (RFC 3758 Section 3.2)。"""

    stream_id: int
    ssn: int


class ForwardTsnChunk(Chunk):
    """Forward TSN (FORWARD-TSN) チャンク (RFC 3758 Section 3.2)。"""

    _CHUNK_TYPE: ClassVar[ChunkType] = ChunkType.FORWARD_TSN

    def __init__(
        self,
        new_cumulative_tsn: int,
        skipped_streams: Iterable[ForwardTsnSkippedStream] = (),
    ) -> None:
        streams = list(skipped_streams)
        value = struct.pack("!I", new_cumulative_tsn)
        for skipped in streams:
            value += struct.pack("!HH", skipped.stream_id, skipped.ssn)
        super().__init__(self._CHUNK_TYPE, value)
        self.new_cumulative_tsn = new_cumulative_tsn
        self.skipped_streams = streams

    @classmethod
    def _parse_value(cls, flags: int, value: bytes) -> ForwardTsnChunk:
        if len(value) < 4 or (len(value) - 4) % 4 != 0:
            raise PacketParseError(f"FORWARD-TSN chunk value has invalid length: {len(value)}")
        (new_cumulative_tsn,) = struct.unpack_from("!I", value)
        streams: list[ForwardTsnSkippedStream] = []
        for offset in range(4, len(value), 4):
            stream_id, ssn = struct.unpack_from("!HH", value, offset)
            streams.append(ForwardTsnSkippedStream(stream_id, ssn))
        return cls(new_cumulative_tsn=new_cumulative_tsn, skipped_streams=streams)


class IForwardTsnSkippedStream(NamedTuple):
    """I-FORWARD-TSN がスキップしたストリームと MID (RFC 8260 Section 2.3.1)。"""

    stream_id: int
    unordered: bool
    mid: int


class IForwardTsnChunk(Chunk):
    """I-FORWARD-TSN チャンク (RFC 8260 Section 2.3.1)。"""

    _CHUNK_TYPE: ClassVar[ChunkType] = ChunkType.I_FORWARD_TSN

    def __init__(
        self,
        new_cumulative_tsn: int,
        skipped_streams: Iterable[IForwardTsnSkippedStream] = (),
    ) -> None:
        streams = list(skipped_streams)
        value = struct.pack("!I", new_cumulative_tsn)
        for skipped in streams:
            value += struct.pack(
                "!HBBI", skipped.stream_id, 0, 1 if skipped.unordered else 0, skipped.mid
            )
        super().__init__(self._CHUNK_TYPE, value)
        self.new_cumulative_tsn = new_cumulative_tsn
        self.skipped_streams = streams

    @classmethod
    def _parse_value(cls, flags: int, value: bytes) -> IForwardTsnChunk:
        if len(value) < 4 or (len(value) - 4) % 8 != 0:
            raise PacketParseError(f"I-FORWARD-TSN chunk value has invalid length: {len(value)}")
        (new_cumulative_tsn,) = struct.unpack_from("!I", value)
        streams: list[IForwardTsnSkippedStream] = []
        for offset in range(4, len(value), 8):
            stream_id, _reserved, unordered, mid = struct.unpack_from("!HBBI", value, offset)
            streams.append(IForwardTsnSkippedStream(stream_id, bool(unordered & 1), mid))
        return cls(new_cumulative_tsn=new_cumulative_tsn, skipped_streams=streams)


class ReConfigChunk(Chunk):
    """Re-configuration (RE-CONFIG) チャンク (RFC 6525 Section 3.1)。"""

    _CHUNK_TYPE: ClassVar[ChunkType] = ChunkType.RE_CONFIG

    def __init__(self, parameters: Sequence[Parameter] = ()) -> None:
        super().__init__(self._CHUNK_TYPE, _serialize_parameters(parameters))
        self.parameters = list(parameters)

    @classmethod
    def _parse_value(cls, flags: int, value: bytes) -> ReConfigChunk:
        return cls(parameters=parse_parameters(value))


_CHUNK_PARSERS: dict[int, type[Chunk]] = {
    ChunkType.DATA: DataChunk,
    ChunkType.INIT: InitChunk,
    ChunkType.INIT_ACK: InitAckChunk,
    ChunkType.SACK: SackChunk,
    ChunkType.HEARTBEAT: HeartbeatChunk,
    ChunkType.HEARTBEAT_ACK: HeartbeatAckChunk,
    ChunkType.ABORT: AbortChunk,
    ChunkType.SHUTDOWN: ShutdownChunk,
    ChunkType.SHUTDOWN_ACK: ShutdownAckChunk,
    ChunkType.ERROR: ErrorChunk,
    ChunkType.COOKIE_ECHO: CookieEchoChunk,
    ChunkType.COOKIE_ACK: CookieAckChunk,
    ChunkType.SHUTDOWN_COMPLETE: ShutdownCompleteChunk,
    ChunkType.FORWARD_TSN: ForwardTsnChunk,
    ChunkType.I_DATA: IDataChunk,
    ChunkType.I_FORWARD_TSN: IForwardTsnChunk,
    ChunkType.RE_CONFIG: ReConfigChunk,
}


class Parameter:
    """チャンク内のパラメータ (TLV) の基底クラス。

    未知のパラメータ種別はこのクラスでそのまま表現する。
    """

    def __init__(self, parameter_type: int, value: bytes = b"") -> None:
        self.parameter_type = parameter_type
        self.value = bytes(value)

    @classmethod
    def _parse_value(cls, value: bytes) -> Parameter:
        """パラメータ値を解析してインスタンスを返す。サブクラスで実装する。"""
        raise NotImplementedError

    def to_bytes(self) -> bytes:
        """パラメータヘッダ + 値 + パディングへ直列化する。"""
        length = _TLV_HEADER_SIZE + len(self.value)
        _check_tlv_length(length, "parameter")
        return struct.pack("!HH", self.parameter_type, length) + self.value + _padding(length)

    def __repr__(self) -> str:
        return f"{type(self).__name__}(parameter_type={self.parameter_type}, value={self.value!r})"


class HeartbeatInfoParameter(Parameter):
    """Heartbeat Info パラメータ (RFC 9260 Section 3.3.5)。"""

    def __init__(self, info: bytes) -> None:
        super().__init__(ParameterType.HEARTBEAT_INFO, info)
        self.info = bytes(info)

    @classmethod
    def _parse_value(cls, value: bytes) -> HeartbeatInfoParameter:
        return cls(value)


class StateCookieParameter(Parameter):
    """State Cookie パラメータ (RFC 9260 Section 3.3.3.1.1)。"""

    def __init__(self, cookie: bytes) -> None:
        super().__init__(ParameterType.STATE_COOKIE, cookie)
        self.cookie = bytes(cookie)

    @classmethod
    def _parse_value(cls, value: bytes) -> StateCookieParameter:
        return cls(value)


class SupportedExtensionsParameter(Parameter):
    """Supported Extensions パラメータ (RFC 5061 Section 4.2.7)。"""

    def __init__(self, chunk_types: Iterable[int]) -> None:
        chunk_type_list = [int(chunk_type) & 0xFF for chunk_type in chunk_types]
        super().__init__(ParameterType.SUPPORTED_EXTENSIONS, bytes(chunk_type_list))
        self.chunk_types = chunk_type_list

    @classmethod
    def _parse_value(cls, value: bytes) -> SupportedExtensionsParameter:
        return cls(value)


class ForwardTsnSupportedParameter(Parameter):
    """Forward TSN Supported パラメータ (RFC 3758 Section 3.1)。"""

    def __init__(self) -> None:
        super().__init__(ParameterType.FORWARD_TSN_SUPPORTED)

    @classmethod
    def _parse_value(cls, value: bytes) -> ForwardTsnSupportedParameter:
        if value:
            raise PacketParseError(
                f"Forward TSN Supported parameter must be empty but got {len(value)} bytes"
            )
        return cls()


class ZeroChecksumAcceptableParameter(Parameter):
    """Zero Checksum Acceptable パラメータ (RFC 9653 Section 4)。"""

    def __init__(self, error_detection_method: int) -> None:
        super().__init__(
            ParameterType.ZERO_CHECKSUM_ACCEPTABLE, struct.pack("!I", error_detection_method)
        )
        self.error_detection_method = error_detection_method

    @classmethod
    def _parse_value(cls, value: bytes) -> ZeroChecksumAcceptableParameter:
        if len(value) != 4:
            raise PacketParseError(
                f"Zero Checksum Acceptable parameter must be 4 bytes but got {len(value)}"
            )
        (error_detection_method,) = struct.unpack("!I", value)
        return cls(error_detection_method)


class OutgoingSsnResetRequestParameter(Parameter):
    """Outgoing SSN Reset Request パラメータ (RFC 6525 Section 4.1)。"""

    def __init__(
        self,
        request_sequence_number: int,
        response_sequence_number: int,
        sender_last_assigned_tsn: int,
        stream_ids: Iterable[int] = (),
    ) -> None:
        streams = list(stream_ids)
        value = struct.pack(
            "!III", request_sequence_number, response_sequence_number, sender_last_assigned_tsn
        )
        for stream_id in streams:
            value += struct.pack("!H", stream_id)
        super().__init__(ParameterType.OUTGOING_SSN_RESET_REQUEST, value)
        self.request_sequence_number = request_sequence_number
        self.response_sequence_number = response_sequence_number
        self.sender_last_assigned_tsn = sender_last_assigned_tsn
        self.stream_ids = streams

    @classmethod
    def _parse_value(cls, value: bytes) -> OutgoingSsnResetRequestParameter:
        if len(value) < 12 or len(value) % 2 != 0:
            raise PacketParseError(
                f"Outgoing SSN Reset Request parameter has invalid length: {len(value)}"
            )
        request_sequence_number, response_sequence_number, sender_last_assigned_tsn = (
            struct.unpack_from("!III", value)
        )
        stream_ids = [
            struct.unpack_from("!H", value, offset)[0] for offset in range(12, len(value), 2)
        ]
        return cls(
            request_sequence_number=request_sequence_number,
            response_sequence_number=response_sequence_number,
            sender_last_assigned_tsn=sender_last_assigned_tsn,
            stream_ids=stream_ids,
        )


class IncomingSsnResetRequestParameter(Parameter):
    """Incoming SSN Reset Request パラメータ (RFC 6525 Section 4.2)。"""

    def __init__(self, request_sequence_number: int, stream_ids: Iterable[int] = ()) -> None:
        streams = list(stream_ids)
        value = struct.pack("!I", request_sequence_number)
        for stream_id in streams:
            value += struct.pack("!H", stream_id)
        super().__init__(ParameterType.INCOMING_SSN_RESET_REQUEST, value)
        self.request_sequence_number = request_sequence_number
        self.stream_ids = streams

    @classmethod
    def _parse_value(cls, value: bytes) -> IncomingSsnResetRequestParameter:
        if len(value) < 4 or len(value) % 2 != 0:
            raise PacketParseError(
                f"Incoming SSN Reset Request parameter has invalid length: {len(value)}"
            )
        (request_sequence_number,) = struct.unpack_from("!I", value)
        stream_ids = [
            struct.unpack_from("!H", value, offset)[0] for offset in range(4, len(value), 2)
        ]
        return cls(request_sequence_number=request_sequence_number, stream_ids=stream_ids)


class ReconfigurationResponseParameter(Parameter):
    """Re-configuration Response パラメータ (RFC 6525 Section 4.4)。"""

    def __init__(
        self,
        response_sequence_number: int,
        result: ReconfigurationResponseResult,
        sender_next_tsn: int | None = None,
        receiver_next_tsn: int | None = None,
    ) -> None:
        value = struct.pack("!II", response_sequence_number, int(result))
        if sender_next_tsn is not None and receiver_next_tsn is not None:
            value += struct.pack("!II", sender_next_tsn, receiver_next_tsn)
        super().__init__(ParameterType.RECONFIGURATION_RESPONSE, value)
        self.response_sequence_number = response_sequence_number
        self.result = result
        self.sender_next_tsn = sender_next_tsn
        self.receiver_next_tsn = receiver_next_tsn

    @classmethod
    def _parse_value(cls, value: bytes) -> ReconfigurationResponseParameter:
        if len(value) not in (8, 16):
            raise PacketParseError(
                f"Re-configuration Response parameter has invalid length: {len(value)}"
            )
        response_sequence_number, result_value = struct.unpack_from("!II", value)
        try:
            result = ReconfigurationResponseResult(result_value)
        except ValueError as error:
            raise PacketParseError(f"unknown re-configuration result: {result_value}") from error
        sender_next_tsn: int | None = None
        receiver_next_tsn: int | None = None
        if len(value) == 16:
            sender_next_tsn, receiver_next_tsn = struct.unpack_from("!II", value, 8)
        return cls(
            response_sequence_number=response_sequence_number,
            result=result,
            sender_next_tsn=sender_next_tsn,
            receiver_next_tsn=receiver_next_tsn,
        )


_PARAMETER_PARSERS: dict[int, type[Parameter]] = {
    ParameterType.HEARTBEAT_INFO: HeartbeatInfoParameter,
    ParameterType.STATE_COOKIE: StateCookieParameter,
    ParameterType.SUPPORTED_EXTENSIONS: SupportedExtensionsParameter,
    ParameterType.FORWARD_TSN_SUPPORTED: ForwardTsnSupportedParameter,
    ParameterType.ZERO_CHECKSUM_ACCEPTABLE: ZeroChecksumAcceptableParameter,
    ParameterType.OUTGOING_SSN_RESET_REQUEST: OutgoingSsnResetRequestParameter,
    ParameterType.INCOMING_SSN_RESET_REQUEST: IncomingSsnResetRequestParameter,
    ParameterType.RECONFIGURATION_RESPONSE: ReconfigurationResponseParameter,
}


class ErrorCause:
    """エラー原因 (TLV) の基底クラス。

    dcsctp が個別に解釈するエラー原因もあるが、ここではコードと生の値を保持する。
    """

    def __init__(self, cause_code: int, value: bytes = b"") -> None:
        self.cause_code = cause_code
        self.value = bytes(value)

    @classmethod
    def _parse_value(cls, value: bytes) -> ErrorCause:
        """エラー原因値を解析してインスタンスを返す。サブクラスで実装する。"""
        raise NotImplementedError

    def to_bytes(self) -> bytes:
        """原因コードヘッダ + 値 + パディングへ直列化する。"""
        length = _TLV_HEADER_SIZE + len(self.value)
        _check_tlv_length(length, "error cause")
        return struct.pack("!HH", self.cause_code, length) + self.value + _padding(length)

    def __repr__(self) -> str:
        return f"{type(self).__name__}(cause_code={self.cause_code}, value={self.value!r})"


class MissingMandatoryParameterErrorCause(ErrorCause):
    """Missing Mandatory Parameter エラー原因 (RFC 9260 Section 3.3.10.2)。"""

    def __init__(self, missing_parameters: Iterable[int]) -> None:
        parameters = list(missing_parameters)
        value = struct.pack("!I", len(parameters))
        for parameter_type in parameters:
            value += struct.pack("!H", parameter_type)
        super().__init__(ErrorCauseCode.MISSING_MANDATORY_PARAMETER, value)
        self.missing_parameters = parameters

    @classmethod
    def _parse_value(cls, value: bytes) -> MissingMandatoryParameterErrorCause:
        if len(value) < 4:
            raise PacketParseError(
                f"Missing Mandatory Parameter cause is too short: {len(value)} bytes"
            )
        (count,) = struct.unpack_from("!I", value)
        if len(value) != 4 + count * 2:
            raise PacketParseError(
                f"Missing Mandatory Parameter cause has invalid length: {len(value)} bytes "
                f"for {count} parameters"
            )
        return cls(struct.unpack_from("!H", value, 4 + index * 2)[0] for index in range(count))


class UnrecognizedChunkErrorCause(ErrorCause):
    """Unrecognized Chunk Type エラー原因 (RFC 9260 Section 3.3.10.6)。

    値は問題となったチャンク全体 (ヘッダを含む) を保持する。
    """

    def __init__(self, chunk: bytes) -> None:
        super().__init__(ErrorCauseCode.UNRECOGNIZED_CHUNK_TYPE, chunk)
        self.chunk = bytes(chunk)

    @classmethod
    def _parse_value(cls, value: bytes) -> UnrecognizedChunkErrorCause:
        return cls(value)


class NoUserDataErrorCause(ErrorCause):
    """No User Data エラー原因 (RFC 9260 Section 3.3.10.9)。"""

    def __init__(self, tsn: int) -> None:
        super().__init__(ErrorCauseCode.NO_USER_DATA, struct.pack("!I", tsn))
        self.tsn = tsn

    @classmethod
    def _parse_value(cls, value: bytes) -> NoUserDataErrorCause:
        if len(value) != 4:
            raise PacketParseError(f"No User Data cause must be 4 bytes but got {len(value)}")
        (tsn,) = struct.unpack("!I", value)
        return cls(tsn)


class CookieReceivedWhileShuttingDownErrorCause(ErrorCause):
    """Cookie Received While Shutting Down エラー原因 (RFC 9260 Section 3.3.10.10)。"""

    def __init__(self) -> None:
        super().__init__(ErrorCauseCode.COOKIE_RECEIVED_WHILE_SHUTTING_DOWN)

    @classmethod
    def _parse_value(cls, value: bytes) -> CookieReceivedWhileShuttingDownErrorCause:
        if value:
            raise PacketParseError(
                f"Cookie Received While Shutting Down cause must be empty but got {len(value)}"
            )
        return cls()


class UserInitiatedAbortErrorCause(ErrorCause):
    """User-Initiated Abort エラー原因 (RFC 9260 Section 3.3.10.12)。

    `reason` は dcsctp では UTF-8 文字列として解釈されるが、ここではバイト列の
    まま保持する (ラウンドトリップで失われる情報を作らないため)。
    """

    def __init__(self, reason: bytes = b"") -> None:
        super().__init__(ErrorCauseCode.USER_INITIATED_ABORT, reason)
        self.reason = bytes(reason)

    @classmethod
    def _parse_value(cls, value: bytes) -> UserInitiatedAbortErrorCause:
        return cls(value)


class ProtocolViolationErrorCause(ErrorCause):
    """Protocol Violation エラー原因 (RFC 9260 Section 3.3.10.13)。

    `information` は dcsctp では UTF-8 文字列として解釈されるが、ここではバイト列
    のまま保持する。
    """

    def __init__(self, information: bytes = b"") -> None:
        super().__init__(ErrorCauseCode.PROTOCOL_VIOLATION, information)
        self.information = bytes(information)

    @classmethod
    def _parse_value(cls, value: bytes) -> ProtocolViolationErrorCause:
        return cls(value)


_ERROR_CAUSE_PARSERS: dict[int, type[ErrorCause]] = {
    ErrorCauseCode.MISSING_MANDATORY_PARAMETER: MissingMandatoryParameterErrorCause,
    ErrorCauseCode.UNRECOGNIZED_CHUNK_TYPE: UnrecognizedChunkErrorCause,
    ErrorCauseCode.NO_USER_DATA: NoUserDataErrorCause,
    ErrorCauseCode.COOKIE_RECEIVED_WHILE_SHUTTING_DOWN: CookieReceivedWhileShuttingDownErrorCause,
    ErrorCauseCode.USER_INITIATED_ABORT: UserInitiatedAbortErrorCause,
    ErrorCauseCode.PROTOCOL_VIOLATION: ProtocolViolationErrorCause,
}


def _serialize_parameters(parameters: Sequence[Parameter]) -> bytes:
    """パラメータ列を直列化する。

    dcsctp と同じく、最後のパラメータのパディングはチャンク側のパディングに含める
    ため、チャンク長には含めない (RFC 9260 Section 3.2)。
    """
    data = bytearray()
    for index, parameter in enumerate(parameters):
        encoded = parameter.to_bytes()
        if index == len(parameters) - 1:
            encoded = encoded[: _TLV_HEADER_SIZE + len(parameter.value)]
        data += encoded
    return bytes(data)


def _serialize_error_causes(error_causes: Sequence[ErrorCause]) -> bytes:
    """エラー原因列を直列化する。パディングの扱いはパラメータと同じ。"""
    data = bytearray()
    for index, error_cause in enumerate(error_causes):
        encoded = error_cause.to_bytes()
        if index == len(error_causes) - 1:
            encoded = encoded[: _TLV_HEADER_SIZE + len(error_cause.value)]
        data += encoded
    return bytes(data)


def _parse_tlv_header(data: bytes, what: str) -> tuple[int, int]:
    """TLV ヘッダ (種別, 長さ) を読み、長さを検査する。"""
    if len(data) < _TLV_HEADER_SIZE:
        raise PacketParseError(f"{what} is shorter than its header: {len(data)} bytes")
    type_number, length = struct.unpack_from("!HH", data)
    if length < _TLV_HEADER_SIZE:
        raise PacketParseError(f"{what} has invalid length {length}")
    if length > len(data):
        raise PacketParseError(f"{what} length {length} exceeds available data {len(data)}")
    return type_number, length


def parse_parameters(data: bytes) -> list[Parameter]:
    """INIT/INIT-ACK/HEARTBEAT/RE-CONFIG のパラメータ列を解析する。

    パラメータの並びは 4 バイト境界に整列されている。
    """
    parameters: list[Parameter] = []
    offset = 0
    while offset < len(data):
        parameter_type, length = _parse_tlv_header(data[offset:], "parameter")
        value = bytes(data[offset + _TLV_HEADER_SIZE : offset + length])
        parser = _PARAMETER_PARSERS.get(parameter_type)
        parameters.append(
            parser._parse_value(value) if parser else Parameter(parameter_type, value)
        )
        offset += _round_up_to_four(length)
    return parameters


def parse_error_causes(data: bytes) -> list[ErrorCause]:
    """ABORT/ERROR チャンクのエラー原因列を解析する。"""
    error_causes: list[ErrorCause] = []
    offset = 0
    while offset < len(data):
        cause_code, length = _parse_tlv_header(data[offset:], "error cause")
        value = bytes(data[offset + _TLV_HEADER_SIZE : offset + length])
        parser = _ERROR_CAUSE_PARSERS.get(cause_code)
        error_causes.append(parser._parse_value(value) if parser else ErrorCause(cause_code, value))
        offset += _round_up_to_four(length)
    return error_causes


def parse_chunk(data: bytes) -> Chunk:
    """先頭 1 個のチャンクを解析する。パディングは含めない。"""
    if len(data) < _TLV_HEADER_SIZE:
        raise PacketParseError(f"chunk is shorter than its header: {len(data)} bytes")
    chunk_type, flags, length = struct.unpack_from("!BBH", data)
    if length < _TLV_HEADER_SIZE:
        raise PacketParseError(f"chunk has invalid length {length}")
    if length > len(data):
        raise PacketParseError(f"chunk length {length} exceeds available data {len(data)}")
    value = bytes(data[_TLV_HEADER_SIZE:length])
    parser = _CHUNK_PARSERS.get(chunk_type)
    if parser is None:
        return UnknownChunk(chunk_type, value, flags)
    return parser._parse_value(flags, value)


def parse_chunks(data: bytes) -> list[Chunk]:
    """チャンク列を解析する。4 バイト境界のパディングは読み飛ばす。"""
    chunks: list[Chunk] = []
    offset = 0
    while offset < len(data):
        chunk = parse_chunk(data[offset:])
        chunks.append(chunk)
        offset += _round_up_to_four(_TLV_HEADER_SIZE + len(chunk.value))
    return chunks


class Packet:
    """SCTP パケット (共通ヘッダ + チャンク列) (RFC 9260 Section 3.1)。"""

    def __init__(
        self,
        source_port: int,
        destination_port: int,
        verification_tag: int,
        chunks: Sequence[Chunk],
        checksum: int | None = None,
    ) -> None:
        self.source_port = source_port
        self.destination_port = destination_port
        self.verification_tag = verification_tag
        self.chunks = list(chunks)
        # 解析時のチェックサム。組み立てたパケットでは None (= 直列化時に計算)
        self.checksum = checksum

    @classmethod
    def parse(cls, data: bytes) -> Packet:
        """受信した SCTP パケットを解析する。チェックサムの検証は行わない。"""
        if len(data) < _COMMON_HEADER_SIZE:
            raise PacketParseError(f"packet is shorter than the common header: {len(data)} bytes")
        source_port, destination_port, verification_tag = struct.unpack_from("!HHI", data)
        # SCTP のチェックサムはリトルエンディアンで格納される (RFC 9260 Appendix B)
        checksum = int.from_bytes(data[8:12], "little")
        return cls(
            source_port=source_port,
            destination_port=destination_port,
            verification_tag=verification_tag,
            chunks=parse_chunks(data[_COMMON_HEADER_SIZE:]),
            checksum=checksum,
        )

    def compute_checksum(self) -> int:
        """チェックサムフィールドを 0 としたときの CRC-32C を計算する。"""
        header = struct.pack(
            "!HHII", self.source_port, self.destination_port, self.verification_tag, 0
        )
        chunks = b"".join(chunk.to_bytes() for chunk in self.chunks)
        return crc32c(header + chunks)

    def has_valid_checksum(self) -> bool:
        """解析時のチェックサムがパケット内容と一致するかを返す。"""
        if self.checksum is None:
            return True
        return self.checksum == self.compute_checksum()

    def to_bytes(self, checksum: int | None = None) -> bytes:
        """パケットを直列化する。

        `checksum` を指定するとその値で書き込むため、壊れたチェックサムのパケットを
        意図的に組み立てられる。省略した場合は正しい CRC-32C を計算して書き込む。
        """
        checksum_value = self.compute_checksum() if checksum is None else checksum
        header = struct.pack(
            "!HHI", self.source_port, self.destination_port, self.verification_tag
        ) + checksum_value.to_bytes(4, "little")
        return header + b"".join(chunk.to_bytes() for chunk in self.chunks)

    def __repr__(self) -> str:
        return (
            f"Packet(source_port={self.source_port}, destination_port={self.destination_port}, "
            f"verification_tag=0x{self.verification_tag:08x}, chunks={self.chunks!r})"
        )
