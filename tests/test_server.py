"""asyncio の Server の挙動を確認するテスト。"""

import asyncio

import dcsctp


def test_server_accepts_connection() -> None:
    """接続が確立すると on_connection が呼ばれること。"""

    async def main() -> None:
        server = dcsctp.Server("127.0.0.1", 0)
        async with server:
            assert server.port != 0

            queue: asyncio.Queue[dcsctp.Connection] = asyncio.Queue()
            server.on_connection(queue.put_nowait)

            async with dcsctp.Client("127.0.0.1", server.port) as client:
                assert client.is_connected
                connection = await asyncio.wait_for(queue.get(), 5.0)

                assert connection.is_connected
                assert connection.peer_address[0] == "127.0.0.1"
                assert connection.state == dcsctp.SocketState.Connected

    asyncio.run(main())


def test_server_handles_multiple_clients() -> None:
    """複数クライアントを別々の Connection として扱えること。"""

    async def main() -> None:
        server = dcsctp.Server("127.0.0.1", 0)
        async with server:
            queue: asyncio.Queue[dcsctp.Connection] = asyncio.Queue()
            server.on_connection(queue.put_nowait)

            client1 = dcsctp.Client("127.0.0.1", server.port)
            await client1.connect(timeout=5.0)
            connection1 = await asyncio.wait_for(queue.get(), 5.0)

            client2 = dcsctp.Client("127.0.0.1", server.port)
            await client2.connect(timeout=5.0)
            connection2 = await asyncio.wait_for(queue.get(), 5.0)

            # クライアントごとに別の接続になる
            assert connection1 is not connection2
            assert connection1.peer_address != connection2.peer_address

            await client1.send(stream_id=1, ppid=53, payload=b"one")
            await client2.send(stream_id=1, ppid=53, payload=b"two")

            # それぞれの接続に自分のメッセージだけが届く
            assert (await connection1.recv(timeout=5.0)).payload == b"one"
            assert (await connection2.recv(timeout=5.0)).payload == b"two"

            await client1.close()
            await client2.close()

    asyncio.run(main())


def test_server_close_aborts_connections() -> None:
    """server.close で接続が閉じられ、クライアント側でも検知できること。"""

    async def main() -> None:
        server = dcsctp.Server("127.0.0.1", 0)
        await server.start()

        queue: asyncio.Queue[dcsctp.Connection] = asyncio.Queue()
        server.on_connection(queue.put_nowait)

        client = dcsctp.Client("127.0.0.1", server.port)
        await client.connect(timeout=5.0)
        await asyncio.wait_for(queue.get(), 5.0)

        await server.close()

        # サーバーが ABORT を送るためクライアント側も閉じる
        for _ in range(100):
            if not client.is_connected:
                break
            await asyncio.sleep(0.01)
        assert not client.is_connected
        client.abort()

    asyncio.run(main())


def test_server_run_returns_after_close() -> None:
    """close すると run が終了すること。"""

    async def main() -> None:
        server = dcsctp.Server("127.0.0.1", 0)
        run_task = asyncio.ensure_future(server.run())

        # start() で実際のポートが決まるまで待つ
        for _ in range(100):
            if server.port != 0:
                break
            await asyncio.sleep(0.01)
        assert server.port != 0

        await server.close()
        await asyncio.wait_for(run_task, 5.0)

    asyncio.run(main())
