"""dcsctp の asyncio クライアント。

Sans I/O な `dcsctp.Socket` を UDP トランスポート上で駆動し、
`connect()` / `send()` / `recv()` / `close()` を提供する。
"""

import asyncio
import socket
from collections.abc import AsyncIterator, Callable
from typing import Self

from dcsctp._core import Message, Metrics, Options, Socket, SocketEvent, SocketState
from dcsctp._udp import DatagramProtocol, get_bound_port, normalize_address
from dcsctp.connection import Connection
from dcsctp.exceptions import ConnectError, DcSctpError

__all__ = ["Client"]


class Client:
    """SCTP アソシエーションのクライアント。

    接続に使う UDP ソケットと `dcsctp.Socket` を所有し、`Connection` へ
    処理を委譲する。コールバックは `connect()` の前後どちらでも登録できる。

    Usage:
        client = dcsctp.Client("127.0.0.1", 5000)
        await client.connect()
        await client.send(stream_id=1, ppid=53, payload=b"hello")
        message = await client.recv()
        await client.close()
    """

    def __init__(
        self,
        host: str,
        port: int,
        *,
        local_host: str = "0.0.0.0",
        local_port: int = 0,
        options: Options | None = None,
        connect_timeout: float = 10.0,
    ) -> None:
        """クライアントを初期化する。

        Args:
            host: 接続先ホスト
            port: 接続先ポート
            local_host: ローカルでバインドするアドレス
            local_port: ローカルでバインドするポート (0 なら自動割り当て)
            options: SCTP のオプション。省略した場合はローカル / リモートの
                UDP ポートを反映した既定値を使う
            connect_timeout: `connect()` の既定のタイムアウト (秒)
        """
        self._host = host
        self._port = port
        self._local_host = local_host
        self._local_port = local_port
        self._options = options
        self._connect_timeout = connect_timeout
        self._transport: asyncio.DatagramTransport | None = None
        self._connection: Connection | None = None
        self._on_message_callbacks: list[Callable[[Message], None]] = []
        self._on_connected_callbacks: list[Callable[[], None]] = []
        self._on_closed_callbacks: list[Callable[[], None]] = []
        self._on_error_callbacks: list[Callable[[SocketEvent], None]] = []
        self._on_event_callbacks: list[Callable[[SocketEvent], None]] = []

    @property
    def peer_address(self) -> tuple[str, int]:
        """接続先の (host, port)。"""
        return (self._host, self._port)

    @property
    def is_connected(self) -> bool:
        """アソシエーションが確立済みかどうか。"""
        return self._connection is not None and self._connection.is_connected

    @property
    def state(self) -> SocketState | None:
        """現在のソケット状態。未接続の場合は None。"""
        return None if self._connection is None else self._connection.state

    @property
    def metrics(self) -> Metrics | None:
        """最新のメトリクス。未接続の場合は None。"""
        return None if self._connection is None else self._connection.metrics

    async def connect(self, timeout: float | None = None) -> None:
        """UDP トランスポートを開き、SCTP ハンドシェイクを完了させる。

        Args:
            timeout: 待つ上限 (秒)。None なら `connect_timeout` を使う

        Raises:
            ConnectError: 名前解決に失敗した場合、または確立できなかった場合
            DcSctpError: すでに接続済みの場合
        """
        if self._connection is not None:
            raise DcSctpError("client is already connected")

        loop = asyncio.get_running_loop()
        try:
            infos = await loop.getaddrinfo(self._host, self._port, type=socket.SOCK_DGRAM)
        except socket.gaierror as error:
            raise ConnectError(f"failed to resolve {self._host}:{self._port}") from error
        if not infos:
            raise ConnectError(f"failed to resolve {self._host}:{self._port}")
        remote_address = normalize_address(infos[0][4])

        transport, _ = await loop.create_datagram_endpoint(
            lambda: DatagramProtocol(self._receive_datagram),
            local_addr=(self._local_host, self._local_port),
        )
        self._transport = transport

        options = self._options
        if options is None:
            # SCTP のポートは UDP の実ポートに合わせておく
            options = Options(local_port=get_bound_port(transport), remote_port=self._port)

        sctp_socket = Socket(f"client {self._host}:{self._port}", options)
        sctp_socket.connect()
        # connect() でキューに積まれた INIT は Connection 生成時の初回ドレインで送信される
        connection = Connection(sctp_socket, transport, remote_address)
        self._connection = connection
        self._install_callbacks(connection)

        try:
            await connection.wait_connected(
                timeout if timeout is not None else self._connect_timeout
            )
        except TimeoutError as error:
            self.abort()
            raise ConnectError(f"connect timed out: {self._host}:{self._port}") from error

    async def send(
        self,
        stream_id: int,
        ppid: int,
        payload: bytes,
        *,
        unordered: bool = False,
        lifetime_ms: int | None = None,
        max_retransmissions: int | None = None,
        lifecycle_id: int | None = None,
    ) -> None:
        """メッセージを送信する。"""
        await self._require_connection().send(
            stream_id,
            ppid,
            payload,
            unordered=unordered,
            lifetime_ms=lifetime_ms,
            max_retransmissions=max_retransmissions,
            lifecycle_id=lifecycle_id,
        )

    async def recv(self, timeout: float | None = None) -> Message:
        """受信メッセージを 1 件取り出す。"""
        return await self._require_connection().recv(timeout)

    async def run(self) -> None:
        """接続が閉じるまで待つ。"""
        await self._require_connection().run()

    async def close(self, timeout: float | None = 3.0) -> None:
        """グレースフルシャットダウンして UDP トランスポートも閉じる。"""
        if self._connection is not None:
            await self._connection.close(timeout)
        self._close_transport()

    def abort(self) -> None:
        """非グレースフルに接続を閉じ、UDP トランスポートも閉じる。"""
        if self._connection is not None:
            self._connection.abort()
        self._close_transport()

    def on_message(self, callback: Callable[[Message], None]) -> None:
        """メッセージ受信時のコールバックを登録する。"""
        self._on_message_callbacks.append(callback)
        if self._connection is not None:
            self._connection.on_message(callback)

    def on_connected(self, callback: Callable[[], None]) -> None:
        """アソシエーション確立時のコールバックを登録する。"""
        self._on_connected_callbacks.append(callback)
        if self._connection is not None:
            self._connection.on_connected(callback)

    def on_closed(self, callback: Callable[[], None]) -> None:
        """アソシエーション終了時のコールバックを登録する。"""
        self._on_closed_callbacks.append(callback)
        if self._connection is not None:
            self._connection.on_closed(callback)

    def on_error(self, callback: Callable[[SocketEvent], None]) -> None:
        """エラーイベント発生時のコールバックを登録する。"""
        self._on_error_callbacks.append(callback)
        if self._connection is not None:
            self._connection.on_error(callback)

    def on_event(self, callback: Callable[[SocketEvent], None]) -> None:
        """すべてのソケットイベントを受け取るコールバックを登録する。"""
        self._on_event_callbacks.append(callback)
        if self._connection is not None:
            self._connection.on_event(callback)

    def __aiter__(self) -> AsyncIterator[Message]:
        return self._require_connection().__aiter__()

    async def __aenter__(self) -> Self:
        await self.connect()
        return self

    async def __aexit__(self, exc_type: object, exc_val: object, exc_tb: object) -> None:
        await self.close()

    def _receive_datagram(self, data: bytes, addr: tuple[str, int]) -> None:
        """UDP で受信したパケットを接続へ入力する。"""
        if self._connection is not None:
            self._connection.handle_input(data)

    def _install_callbacks(self, connection: Connection) -> None:
        """`connect()` 前に登録されたコールバックを接続へ反映する。"""
        for callback in self._on_message_callbacks:
            connection.on_message(callback)
        for callback in self._on_connected_callbacks:
            connection.on_connected(callback)
        for callback in self._on_closed_callbacks:
            connection.on_closed(callback)
        for callback in self._on_error_callbacks:
            connection.on_error(callback)
        for callback in self._on_event_callbacks:
            connection.on_event(callback)

    def _require_connection(self) -> Connection:
        """接続済みの `Connection` を返す。"""
        if self._connection is None:
            raise DcSctpError("client is not connected")
        return self._connection

    def _close_transport(self) -> None:
        """UDP トランスポートを閉じる。"""
        if self._transport is not None:
            self._transport.close()
            self._transport = None
