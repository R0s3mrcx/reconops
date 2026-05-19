from __future__ import annotations
from fastapi import WebSocket
import asyncio


class ConnectionManager:
    def __init__(self) -> None:
        self._rooms: dict[str, list[WebSocket]] = {}

    async def connect(self, room: str, ws: WebSocket) -> None:
        await ws.accept()
        self._rooms.setdefault(room, []).append(ws)

    def disconnect(self, room: str, ws: WebSocket) -> None:
        if room in self._rooms:
            try:
                self._rooms[room].remove(ws)
            except ValueError:
                pass

    async def broadcast(self, room: str, data: dict) -> None:
        dead: list[WebSocket] = []
        for ws in self._rooms.get(room, []):
            try:
                await ws.send_json(data)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(room, ws)


ws_manager = ConnectionManager()
