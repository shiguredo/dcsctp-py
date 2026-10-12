"""asyncio の Connection の低レイヤー挙動を確認するテスト。

実 UDP の loopback 上で Client / Server を動かし、メッセージの受け渡しと
コールバック、閉じた後の挙動を検証する。
"""

import asyncio

import dcsctp
import pytest


def test_recv_timeout() -> None:
    """メッセージが来ない場合に recv が TimeoutError になること。"""

    async def main() -> None:
        server = dcsctp.Server("127.0.0.1", 0)
        async with server:
            # サーバー側の接続を先に受け付けてから受信を待つ
            queue: asyncio.Queue[dcsctp.Connection] = asyncio.Queue()
            server.on_connection(queue.put_nowait)

            async with dcsctp.Client("127.0.0.1", server.port) as _:
                connection = await asyncio.wait_for(queue.get(), 5.0)
                with pytest.raises(TimeoutError):
                    await connection.recv(timeout=0.05)

    asyncio.run(main())


def test_recv_after_close_raises() -> None:
    """接続が閉じた後の recv が ConnectionClosedError になること。"""

    async def main() -> None:
        server = dcsctp.Server("127.0.0.1", 0)
        async with server:
            queue: asyncio.Queue[dcsctp.Connection] = asyncio.Queue()
            server.on_connection(queue.put_nowait)

            async with dcsctp.Client("127.0.0.1", server.port) as client:
                connection = await asyncio.wait_for(queue.get(), 5.0)
                # クライアントを閉じるとサーバー側も閉じる
                await client.close()
                for _ in range(100):
                    if connection.state == dcsctp.SocketState.Closed:
                        break
                    await asyncio.sleep(0.01)
                assert connection.state == dcsctp.SocketState.Closed

                with pytest.raises(dcsctp.ConnectionClosedError):
                    await connection.recv(timeout=1.0)

    asyncio.run(main())


def test_on_message_callback() -> None:
    """on_message のコールバックでメッセージを受け取れること。"""

    async def main() -> None:
        server = dcsctp.Server("127.0.0.1", 0)
        async with server:
            queue: asyncio.Queue[dcsctp.Connection] = asyncio.Queue()
            server.on_connection(queue.put_nowait)

            async with dcsctp.Client("127.0.0.1", server.port) as client:
                connection = await asyncio.wait_for(queue.get(), 5.0)
                messages: list[dcsctp.Message] = []
                connection.on_message(messages.append)

                await client.send(stream_id=1, ppid=53, payload=b"callback")
                for _ in range(100):
                    if messages:
                        break
                    await asyncio.sleep(0.01)

                assert len(messages) == 1
                assert messages[0].stream_id == 1
                assert messages[0].ppid == 53
                assert messages[0].payload == b"callback"

    asyncio.run(main())


def test_on_closed_callback() -> None:
    """接続終了時に on_closed のコールバックが呼ばれること。"""

    async def main() -> None:
        server = dcsctp.Server("127.0.0.1", 0)
        async with server:
            queue: asyncio.Queue[dcsctp.Connection] = asyncio.Queue()
            server.on_connection(queue.put_nowait)

            async with dcsctp.Client("127.0.0.1", server.port) as client:
                connection = await asyncio.wait_for(queue.get(), 5.0)
                closed = asyncio.Event()
                connection.on_closed(closed.set)

                await client.close()
                await asyncio.wait_for(closed.wait(), 5.0)

    asyncio.run(main())


def test_async_iteration() -> None:
    """Connection を async for で回してメッセージを取り出せること。"""

    async def main() -> None:
        server = dcsctp.Server("127.0.0.1", 0)
        async with server:
            queue: asyncio.Queue[dcsctp.Connection] = asyncio.Queue()
            server.on_connection(queue.put_nowait)

            async with dcsctp.Client("127.0.0.1", server.port) as client:
                connection = await asyncio.wait_for(queue.get(), 5.0)
                await client.send(stream_id=1, ppid=53, payload=b"one")
                await client.send(stream_id=1, ppid=53, payload=b"two")

                received: list[bytes] = []
                async for message in connection:
                    received.append(message.payload)
                    if len(received) == 2:
                        break

                assert received == [b"one", b"two"]

    asyncio.run(main())


def test_abort() -> None:
    """abort で即時に閉じること。"""

    async def main() -> None:
        server = dcsctp.Server("127.0.0.1", 0)
        async with server:
            queue: asyncio.Queue[dcsctp.Connection] = asyncio.Queue()
            server.on_connection(queue.put_nowait)

            client = dcsctp.Client("127.0.0.1", server.port)
            await client.connect(timeout=5.0)
            await asyncio.wait_for(queue.get(), 5.0)

            client.abort()
            assert not client.is_connected
            assert client.state == dcsctp.SocketState.Closed

    asyncio.run(main())
