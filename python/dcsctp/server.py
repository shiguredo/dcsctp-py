"""dcsctp の asyncio サーバー。

UDP で待ち受け、ピアごとに `dcsctp.Socket` と `Connection` を生成する
(1 ソケット 1 アソシエーション)。
"""

import asyncio
from collections.abc import Callable
from typing import Self

from dcsctp._core import Options, Socket
from dcsctp._udp import DatagramProtocol, get_bound_port
from dcsctp.connection import Connection
from dcsctp.exceptions import DcSctpError

__all__ = ["Server"]


class Server:
    """UDP で待ち受け、ピアごとに `Connection` を生成するサーバー。

    接続が確立すると `on_connection` のコールバックが `Connection` を
    引数に呼ばれる。コールバックは接続ごとに 1 回だけ呼ばれる。

    Usage:
        server = dcsctp.Server("0.0.0.0", 5000)
        server.on_connection(lambda connection: ...)

        async with server:
            await server.run()
    """

    def __init__(self, host: str, port: int, *, options: Options | None = None) -> None:
        """サーバーを初期化する。

        Args:
            host: 待ち受けるアドレス
            port: 待ち受けるポート (0 なら自動割り当て)
            options: SCTP のオプション。省略した場合はピアごとに UDP の
                実ポートを反映した既定値を使う
        """
        self._host = host
        self._port = port
        self._options = options
        self._transport: asyncio.DatagramTransport | None = None
        self._connections: dict[tuple[str, int], Connection] = {}
        self._on_connection_callbacks: list[Callable[[Connection], None]] = []
        self._closed = asyncio.Event()

    @property
    def host(self) -> str:
        """待ち受けているアドレス。"""
        return self._host

    @property
    def port(self) -> int:
        """実際に待ち受けているポート番号。未起動なら指定されたポート。"""
        if self._transport is None:
            return self._port
        return get_bound_port(self._transport)

    async def start(self) -> None:
        """UDP ソケットをバインドして待ち受けを開始する。"""
        if self._transport is not None:
            return
        loop = asyncio.get_running_loop()
        transport, _ = await loop.create_datagram_endpoint(
            lambda: DatagramProtocol(self._receive_datagram),
            local_addr=(self._host, self._port),
        )
        self._transport = transport

    async def close(self) -> None:
        """接続をすべて ABORT で切り、待ち受けを終了する。"""
        for connection in list(self._connections.values()):
            connection.abort()
        self._connections.clear()
        if self._transport is not None:
            self._transport.close()
            self._transport = None
        self._closed.set()

    async def run(self) -> None:
        """待ち受けを開始し、`close()` されるまで待つ。"""
        await self.start()
        await self._closed.wait()

    def on_connection(self, callback: Callable[[Connection], None]) -> None:
        """接続確立時のコールバックを登録する。"""
        self._on_connection_callbacks.append(callback)

    async def __aenter__(self) -> Self:
        await self.start()
        return self

    async def __aexit__(self, exc_type: object, exc_val: object, exc_tb: object) -> None:
        await self.close()

    def _receive_datagram(self, data: bytes, addr: tuple[str, int]) -> None:
        """UDP で受信したパケットを、ピアに対応する接続へ入力する。"""
        connection = self._connections.get(addr)
        if connection is None:
            connection = self._create_connection(addr)
            self._connections[addr] = connection
        connection.handle_input(data)

    def _create_connection(self, addr: tuple[str, int]) -> Connection:
        """ピア用の `Socket` と `Connection` を生成する。"""
        if self._transport is None:
            raise DcSctpError("server is not started")
        options = self._options
        if options is None:
            # SCTP のポートは UDP の実ポートに合わせておく
            options = Options(local_port=self.port, remote_port=addr[1])
        socket = Socket(f"server {self._host}:{self.port}", options)
        connection = Connection(socket, self._transport, addr)
        connection.on_connected(lambda: self._notify_connection(connection))
        # 閉じた接続はピアのアドレスごと破棄する
        connection.on_closed(lambda: self._remove_connection(addr))
        return connection

    def _remove_connection(self, addr: tuple[str, int]) -> None:
        """閉じた接続をピアのアドレスから削除する。"""
        self._connections.pop(addr, None)

    def _notify_connection(self, connection: Connection) -> None:
        """接続確立をコールバックへ通知する。"""
        for callback in self._on_connection_callbacks:
            callback(connection)
