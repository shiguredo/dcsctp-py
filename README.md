# dcsctp-py

[dcsctp](https://github.com/webrtc/dcsctp) の Python バインディングです。

dcsctp は WebRTC Data Channel 向けの SCTP 実装です。dcsctp-py は asyncio API と、SCTP パケットをバイト列で入出力する Sans I/O API、パケットやチャンクを低レイヤーで解析するテスト用 API を提供します。

## インストール

```bash
uv add dcsctp
```

## 使い方

### asyncio

```python
import asyncio

import dcsctp


async def main() -> None:
    server = dcsctp.Server("127.0.0.1", 0)

    connections: asyncio.Queue[dcsctp.Connection] = asyncio.Queue()
    server.on_connection(connections.put_nowait)

    async with server:
        async with dcsctp.Client("127.0.0.1", server.port) as client:
            await client.send(stream_id=1, ppid=53, payload=b"hello")

            connection = await connections.get()
            message = await connection.recv()
            print(f"受信: {message.payload}")

            await connection.send(stream_id=1, ppid=53, payload=b"world")
            reply = await client.recv()
            print(f"受信: {reply.payload}")


asyncio.run(main())
```

### Sans I/O

`dcsctp.Socket` は I/O を持たない低レベル API です。パケットの送受信と仮想時刻の進行は利用者が行います。`dcsctp.Packet` でパケットやチャンクを解析・組み立てできます。

```python
import dcsctp

client = dcsctp.Socket("client")
server = dcsctp.Socket("server")

# ハンドシェイク
client.connect()
for _ in range(10):
    for sock, peer in ((client, server), (server, client)):
        while (event := sock.poll_event()) is not None:
            if event.kind == "send_packet" and event.data is not None:
                peer.handle_input(event.data)

# メッセージ送信
client.send(dcsctp.Message(stream_id=1, ppid=53, payload=b"hello"))
```

## 開発

```bash
uv sync
uv run maturin develop
uv run pytest

# git フック (ruff / ty / cargo fmt / cargo clippy / pytest) を導入する
prek install --prepare-hooks
```

## ライセンス

Apache License 2.0

```text
Copyright 2026 Shiguredo Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```
