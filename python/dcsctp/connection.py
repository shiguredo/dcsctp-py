"""1 個の SCTP アソシエーションを asyncio で駆動する `Connection`。

`dcsctp.Socket` は Sans I/O なので、このモジュールが UDP トランスポートとの
橋渡しと、仮想時刻の進行 (`poll_timeout` / `advance_time`) を担当する。
`Client.connect()` と `Server` が返す接続ハンドルはすべてこのクラスである。
"""

import asyncio
from collections.abc import Callable
from typing import Self

from dcsctp._core import Message, Metrics, Options, SendOptions, Socket, SocketEvent, SocketState
from dcsctp.exceptions import ConnectError, ConnectionClosedError

__all__ = ["Connection"]


class Connection:
    """asyncio 上で 1 個の SCTP アソシエーションを駆動するハンドル。

    `Client.connect()` または `Server` が生成する。UDP トランスポートの
    所有権は持たず、`close()` / `abort()` してもトランスポートは閉じない
    (所有権は `Client` / `Server` にある)。

    受信メッセージは `on_message` のコールバックと `recv()` のキューの
    両方へ配られる。コールバックだけを使う場合でもキューに溜まり続けるため、
    長時間動かす場合は `recv()` で取り出すか、キューを捨てる方針を決めること。

    Usage:
        client = dcsctp.Client("127.0.0.1", 5000)
        await client.connect()
        await client.send(stream_id=1, ppid=53, payload=b"hello")
        await client.close()
    """

    def __init__(
        self,
        socket: Socket,
        transport: asyncio.DatagramTransport,
        remote_address: tuple[str, int],
    ) -> None:
        """接続ハンドルを初期化する。

        イベントループ上で呼ぶこと。

        Args:
            socket: このアソシエーションを処理する Sans I/O ソケット
            transport: パケットを送受信する UDP トランスポート
            remote_address: 送信先の (host, port)
        """
        self._socket = socket
        self._transport = transport
        self._remote_address = remote_address
        self._loop = asyncio.get_running_loop()
        self._start_time = self._loop.time()
        self._timer_handle: asyncio.TimerHandle | None = None
        self._messages: asyncio.Queue[Message] = asyncio.Queue()
        self._connected = asyncio.Event()
        self._closed = asyncio.Event()
        self._on_message_callbacks: list[Callable[[Message], None]] = []
        self._on_connected_callbacks: list[Callable[[], None]] = []
        self._on_closed_callbacks: list[Callable[[], None]] = []
        self._on_error_callbacks: list[Callable[[SocketEvent], None]] = []
        self._on_event_callbacks: list[Callable[[SocketEvent], None]] = []
        # 生成前にキューへ積まれたイベント (INIT の送信など) をここで処理する
        self._drain()

    @property
    def peer_address(self) -> tuple[str, int]:
        """ピアの (host, port)。"""
        return self._remote_address

    @property
    def state(self) -> SocketState:
        """現在のソケット状態。"""
        return self._socket.state()

    @property
    def is_connected(self) -> bool:
        """アソシエーションが確立済みかどうか。"""
        return self._socket.state() == SocketState.Connected

    @property
    def metrics(self) -> Metrics | None:
        """最新のメトリクス。未接続の場合は None。"""
        return self._socket.get_metrics()

    @property
    def options(self) -> Options:
        """この接続の実効オプション。"""
        return self._socket.options()

    def on_message(self, callback: Callable[[Message], None]) -> None:
        """メッセージ受信時のコールバックを登録する。"""
        self._on_message_callbacks.append(callback)

    def on_connected(self, callback: Callable[[], None]) -> None:
        """アソシエーション確立時のコールバックを登録する。"""
        self._on_connected_callbacks.append(callback)

    def on_closed(self, callback: Callable[[], None]) -> None:
        """アソシエーション終了時のコールバックを登録する。"""
        self._on_closed_callbacks.append(callback)

    def on_error(self, callback: Callable[[SocketEvent], None]) -> None:
        """エラーイベント発生時のコールバックを登録する。"""
        self._on_error_callbacks.append(callback)

    def on_event(self, callback: Callable[[SocketEvent], None]) -> None:
        """すべてのソケットイベントを受け取るコールバックを登録する。"""
        self._on_event_callbacks.append(callback)

    def handle_input(self, data: bytes) -> None:
        """受信した SCTP パケットを入力してイベントを処理する。

        通常は asyncio のトランスポートが呼ぶ。低レイヤーのテストで
        手動入力したい場合にも使える。
        """
        self._socket.handle_input(data)
        self._drain()

    async def wait_connected(self, timeout: float | None = None) -> None:
        """アソシエーションが確立するまで待つ。

        Args:
            timeout: 待つ上限 (秒)。None なら無期限

        Raises:
            ConnectError: 確立前に接続が閉じた場合
            TimeoutError: timeout を過ぎた場合
        """
        if self._connected.is_set():
            return
        if self._closed.is_set():
            raise ConnectError("connection was closed before it was established")
        await asyncio.wait_for(self._connected.wait(), timeout)

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
        """メッセージを送信する。

        未接続でも呼べる (dcsctp が送信キューへ積み、接続後に送信する)。

        Args:
            stream_id: 送信するストリーム ID
            ppid: Payload Protocol Identifier
            payload: 送信するデータ
            unordered: 順序保証をしない場合は True
            lifetime_ms: 部分信頼性の生存期間 (ミリ秒)
            max_retransmissions: 最大再送回数
            lifecycle_id: ライフサイクル識別子 (0 以外)

        Raises:
            ValueError: 空のペイロードなど、同期的に検出できる送信エラー
            RuntimeError: 送信キューが満杯、またはソケットが閉じている場合
        """
        message = Message(stream_id=stream_id, ppid=ppid, payload=payload)
        send_options = SendOptions(
            unordered=unordered,
            lifetime_ms=lifetime_ms,
            max_retransmissions=max_retransmissions,
            lifecycle_id=lifecycle_id,
        )
        self._socket.send(message, send_options)
        self._drain()

    async def recv(self, timeout: float | None = None) -> Message:
        """受信メッセージを 1 件取り出す。

        Args:
            timeout: 待つ上限 (秒)。None なら無期限

        Returns:
            受信したメッセージ

        Raises:
            ConnectionClosedError: 接続が閉じ、未処理のメッセージも無い場合
            TimeoutError: timeout を過ぎた場合
        """
        if not self._messages.empty():
            return self._messages.get_nowait()
        if self._closed.is_set():
            raise ConnectionClosedError("connection is closed")

        # メッセージ到着と接続終了のどちらか早い方まで待つ
        message_task: asyncio.Task[Message] = asyncio.ensure_future(self._messages.get())
        closed_task: asyncio.Task[bool] = asyncio.ensure_future(self._closed.wait())
        try:
            done, _ = await asyncio.wait(
                {message_task, closed_task},
                timeout=timeout,
                return_when=asyncio.FIRST_COMPLETED,
            )
        finally:
            for task in (message_task, closed_task):
                if not task.done():
                    task.cancel()
            await asyncio.gather(message_task, closed_task, return_exceptions=True)

        if message_task in done:
            return message_task.result()
        if closed_task in done:
            raise ConnectionClosedError("connection is closed")
        raise TimeoutError("timed out waiting for a message")

    async def run(self) -> None:
        """接続が閉じるまで待つ。"""
        await self._closed.wait()

    async def close(self, timeout: float | None = 3.0) -> None:
        """グレースフルシャットダウンして接続を閉じる。

        Args:
            timeout: シャットダウンの完了を待つ上限 (秒)。None なら無期限。
                過ぎた場合は非グレースフルな `abort()` に切り替える
        """
        if self._closed.is_set():
            return
        if self._socket.state() == SocketState.Closed:
            self._mark_closed()
            return
        # 送信中のデータを送り切って SHUTDOWN を交換する
        self._socket.shutdown()
        self._drain()
        try:
            await asyncio.wait_for(self._closed.wait(), timeout)
        except TimeoutError:
            self.abort()

    def abort(self) -> None:
        """非グレースフルに接続を閉じる (ABORT を送る)。"""
        if self._closed.is_set():
            return
        self._socket.close()
        self._drain()
        self._mark_closed()

    def __aiter__(self) -> Self:
        return self

    async def __anext__(self) -> Message:
        try:
            return await self.recv()
        except ConnectionClosedError:
            raise StopAsyncIteration from None

    def _drain(self) -> None:
        """ソケットのイベントと受信メッセージを処理し、タイマーを張り直す。"""
        while (event := self._socket.poll_event()) is not None:
            self._handle_event(event)
        while (message := self._socket.get_next_message()) is not None:
            self._messages.put_nowait(message)
            for callback in self._on_message_callbacks:
                callback(message)
        self._schedule_timeout()

    def _handle_event(self, event: SocketEvent) -> None:
        """1 個のソケットイベントを処理する。"""
        if event.kind == "send_packet" and event.data is not None:
            self._transport.sendto(event.data, self._remote_address)
        elif event.kind == "connected":
            self._connected.set()
            for callback in self._on_connected_callbacks:
                callback()
        elif event.kind == "closed":
            self._closed.set()
            for callback in self._on_closed_callbacks:
                callback()
        elif event.kind == "aborted":
            # ピアからの ABORT や再試行超過による終了
            self._closed.set()
            for callback in self._on_error_callbacks:
                callback(event)
            for callback in self._on_closed_callbacks:
                callback()
        elif event.kind == "error":
            for callback in self._on_error_callbacks:
                callback(event)
        for callback in self._on_event_callbacks:
            callback(event)

    def _mark_closed(self) -> None:
        """閉じた状態にしてタイマーを止める。"""
        self._closed.set()
        self._cancel_timer()

    def _schedule_timeout(self) -> None:
        """`poll_timeout()` の期限に合わせてタイマーを張り直す。"""
        self._cancel_timer()
        if self._closed.is_set():
            return
        deadline = self._socket.poll_timeout()
        if deadline is None:
            return
        delay = max(0.0, (deadline - self._elapsed_ms()) / 1000)
        self._timer_handle = self._loop.call_later(delay, self._on_timeout)

    def _cancel_timer(self) -> None:
        """張ってあるタイマーをキャンセルする。"""
        if self._timer_handle is not None:
            self._timer_handle.cancel()
            self._timer_handle = None

    def _on_timeout(self) -> None:
        """仮想時刻を進めてタイマー起因のイベントを処理する。"""
        self._timer_handle = None
        if self._closed.is_set():
            return
        self._socket.advance_time(self._elapsed_ms())
        self._drain()

    def _elapsed_ms(self) -> int:
        """ソケット生成からの経過時間 (ミリ秒) を返す。"""
        return int((self._loop.time() - self._start_time) * 1000)
