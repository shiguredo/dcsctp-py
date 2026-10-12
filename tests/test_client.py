"""asyncio の Client の挙動を確認するテスト。"""

import asyncio
import socket

import dcsctp
import pytest


def test_client_connect_and_send_recv() -> None:
    """クライアントが接続し、サーバー側とメッセージを交換できること。"""

    async def main() -> None:
        server = dcsctp.Server("127.0.0.1", 0)
        async with server:
            queue: asyncio.Queue[dcsctp.Connection] = asyncio.Queue()
            server.on_connection(queue.put_nowait)

            async with dcsctp.Client("127.0.0.1", server.port) as client:
                assert client.is_connected
                assert client.peer_address == ("127.0.0.1", server.port)

                connection = await asyncio.wait_for(queue.get(), 5.0)
                assert connection.is_connected

                # 双方向にメッセージを交換する
                await client.send(stream_id=1, ppid=53, payload=b"ping")
                received = await connection.recv(timeout=5.0)
                assert received.stream_id == 1
                assert received.ppid == 53
                assert received.payload == b"ping"

                await connection.send(stream_id=2, ppid=51, payload=b"pong")
                reply = await client.recv(timeout=5.0)
                assert reply.stream_id == 2
                assert reply.ppid == 51
                assert reply.payload == b"pong"

    asyncio.run(main())


def test_client_on_message_callback() -> None:
    """connect 前に登録した on_message が接続後も生きること。"""

    async def main() -> None:
        server = dcsctp.Server("127.0.0.1", 0)
        async with server:
            queue: asyncio.Queue[dcsctp.Connection] = asyncio.Queue()
            server.on_connection(queue.put_nowait)

            messages: list[dcsctp.Message] = []
            async with dcsctp.Client("127.0.0.1", server.port) as client:
                # connect() の前にコールバックを登録する
                client.on_message(messages.append)
                connection = await asyncio.wait_for(queue.get(), 5.0)
                await connection.send(stream_id=1, ppid=53, payload=b"early")

                for _ in range(100):
                    if messages:
                        break
                    await asyncio.sleep(0.01)
                assert [message.payload for message in messages] == [b"early"]

    asyncio.run(main())


def test_client_run_returns_after_close() -> None:
    """close すると run が終了すること。"""

    async def main() -> None:
        server = dcsctp.Server("127.0.0.1", 0)
        async with server:
            queue: asyncio.Queue[dcsctp.Connection] = asyncio.Queue()
            server.on_connection(queue.put_nowait)

            client = dcsctp.Client("127.0.0.1", server.port)
            await client.connect(timeout=5.0)
            await asyncio.wait_for(queue.get(), 5.0)

            run_task = asyncio.ensure_future(client.run())
            await client.close()
            await asyncio.wait_for(run_task, 5.0)

    asyncio.run(main())


def test_client_connect_timeout() -> None:
    """応答が無い場合は ConnectError になり、後始末されること。"""

    async def main() -> None:
        # 誰も待ち受けていないポートへ接続する
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        probe.bind(("127.0.0.1", 0))
        closed_port = probe.getsockname()[1]
        probe.close()

        client = dcsctp.Client("127.0.0.1", closed_port)
        with pytest.raises(dcsctp.ConnectError, match="connect timed out"):
            await client.connect(timeout=0.2)
        assert not client.is_connected
        assert client.state == dcsctp.SocketState.Closed

    asyncio.run(main())


def test_client_retransmits_init_on_timeout() -> None:
    """INIT が RTO で再送されること (asyncio 層のタイマー駆動の確認)。

    応答しない偽サーバーの UDP ソケットで INIT を受信し、同じ initiate_tag を
    持つ INIT がもう一度届くことを確認する。
    """

    async def main() -> None:
        loop = asyncio.get_running_loop()
        fake_server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        fake_server.bind(("127.0.0.1", 0))
        fake_server.setblocking(False)
        fake_server_port = fake_server.getsockname()[1]

        try:
            # T1-init を短くして再送を待ちやすくする
            options = dcsctp.Options(t1_init_timeout_ms=200)
            client = dcsctp.Client("127.0.0.1", fake_server_port, options=options)
            connect_task = asyncio.ensure_future(client.connect(timeout=2.0))

            # 最初の INIT
            first_data, _ = await asyncio.wait_for(loop.sock_recvfrom(fake_server, 65535), 1.0)
            first_packet = dcsctp.Packet.parse(first_data)
            first_init = first_packet.chunks[0]
            assert isinstance(first_init, dcsctp.InitChunk)

            # T1-init の経過で同じ INIT が再送される
            second_data, _ = await asyncio.wait_for(loop.sock_recvfrom(fake_server, 65535), 2.0)
            second_init = dcsctp.Packet.parse(second_data).chunks[0]
            assert isinstance(second_init, dcsctp.InitChunk)
            assert second_init.initiate_tag == first_init.initiate_tag

            # 応答しないままタイムアウトする
            with pytest.raises(dcsctp.ConnectError):
                await connect_task
        finally:
            fake_server.close()

    asyncio.run(main())


def test_client_connect_twice_raises() -> None:
    """接続済みの Client に再度 connect するとエラーになること。"""

    async def main() -> None:
        server = dcsctp.Server("127.0.0.1", 0)
        async with server:
            queue: asyncio.Queue[dcsctp.Connection] = asyncio.Queue()
            server.on_connection(queue.put_nowait)

            async with dcsctp.Client("127.0.0.1", server.port) as client:
                await asyncio.wait_for(queue.get(), 5.0)
                with pytest.raises(dcsctp.DcSctpError, match="already connected"):
                    await client.connect()

    asyncio.run(main())
