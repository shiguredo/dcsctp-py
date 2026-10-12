"""dcsctp の asyncio API で発生する例外。"""

__all__ = ["ConnectError", "ConnectionClosedError", "DcSctpError"]


class DcSctpError(Exception):
    """dcsctp の asyncio API で発生するエラーの基底クラス。"""


class ConnectError(DcSctpError):
    """SCTP アソシエーションの確立に失敗したことを表す。"""


class ConnectionClosedError(DcSctpError):
    """接続がすでに閉じていることを表す。"""
