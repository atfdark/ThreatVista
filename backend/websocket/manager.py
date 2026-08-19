import asyncio
from fastapi import WebSocket, WebSocketDisconnect
from typing import List
import json


class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []
        self._loop: Optional[asyncio.AbstractEventLoop] = None

    def set_loop(self, loop: asyncio.AbstractEventLoop):
        self._loop = loop

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        try:
            self._loop = asyncio.get_running_loop()
        except RuntimeError:
            pass

    def disconnect(self, websocket: WebSocket):
        try:
            self.active_connections.remove(websocket)
        except ValueError:
            pass

    async def broadcast(self, message: dict):
        """Send a message to all connected clients, cleaning up dead ones."""
        dead = []
        for connection in list(self.active_connections):
            try:
                await connection.send_json(message)
            except Exception:
                dead.append(connection)
        for conn in dead:
            try:
                self.active_connections.remove(conn)
            except ValueError:
                pass

    def broadcast_nowait(self, message: dict):
        """Fire-and-forget broadcast via asyncio task or threadsafe dispatch.

        Used by batch endpoints and background AI threads so messages
        reach WebSocket clients immediately without blocking. Safe to call
        from both async functions and background worker threads.
        """
        loop = self._loop
        if not loop or loop.is_closed():
            try:
                loop = asyncio.get_running_loop()
                self._loop = loop
            except RuntimeError:
                loop = None

        if loop and not loop.is_closed():
            try:
                current_loop = asyncio.get_running_loop()
                if current_loop is loop:
                    loop.create_task(self.broadcast(message))
                else:
                    asyncio.run_coroutine_threadsafe(self.broadcast(message), loop)
            except RuntimeError:
                # We are in a background worker thread
                asyncio.run_coroutine_threadsafe(self.broadcast(message), loop)


manager = ConnectionManager()
