"""asyncio の UDP トランスポートとアドレス正規化の共通処理。

`client` / `server` が共有する `DatagramProtocol` と、受信アドレス・
バインド済みポートの取り出しを置く。
"""

import asyncio
from collections.abc import Callable

from dcsctp.exceptions import DcSctpError

# getaddrinfo / recvfrom は IPv4 では 2 要素、IPv6 では 4 要素のタプルを返す。
# AF_UNIX などでは別の形になるため、受け取った側で検証する
Address = tuple[str, int] | tuple[str, int, int, int] | tuple[int, bytes]


def normalize_address(addr: Address) -> tuple[str, int]:
    """IPv4 / IPv6 どちらのアドレスも (host, port) に正規化する。

    Args:
        addr: `getaddrinfo` や `DatagramProtocol` が返したアドレス

    Returns:
        (host, port) の 2 要素タプル

    Raises:
        DcSctpError: IPv4 / IPv6 のアドレスとして解釈できなかった場合
    """
    host = addr[0]
    port = addr[1] if len(addr) >= 2 else None
    if not isinstance(host, str) or not isinstance(port, int):
        raise DcSctpError(f"invalid address: {addr!r}")
    return (host, port)


def get_bound_port(transport: asyncio.DatagramTransport) -> int:
    """バインド済み UDP ソケットの実際のポート番号を返す。

    Args:
        transport: バインド済みの UDP トランスポート

    Returns:
        実際にバインドされたポート番号

    Raises:
        DcSctpError: ソケット名からポート番号を取り出せなかった場合
    """
    sockname = transport.get_extra_info("sockname")
    if not isinstance(sockname, tuple) or len(sockname) < 2 or not isinstance(sockname[1], int):
        raise DcSctpError(f"failed to get the bound port: {sockname!r}")
    return sockname[1]


class DatagramProtocol(asyncio.DatagramProtocol):
    """受信したデータグラムをコールバックへ渡すだけの DatagramProtocol。

    SCTP の処理は `Connection` が行うため、ここでは受信の入口だけを提供する。
    """

    def __init__(self, handler: Callable[[bytes, tuple[str, int]], None]) -> None:
        """コールバックを登録する。

        Args:
            handler: (受信データ, 送信元アドレス) を受け取るコールバック
        """
        self._handler = handler

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        """データグラム受信時に呼ばれる。"""
        self._handler(data, normalize_address(addr))

    def error_received(self, exc: Exception) -> None:
        """UDP の ICMP エラー通知。

        port unreachable などは SCTP の再送に任せるため、ここでは何もしない。
        """
