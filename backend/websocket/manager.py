import asyncio
from fastapi import WebSocket, WebSocketDisconnect
from typing import List
import json


class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        try:
            self.active_connections.remove(websocket)
        except ValueError:
            pass

    async def broadcast(self, message: dict):
        """Send a message to all connected clients, cleaning up dead ones."""
        dead = []
        for connection in self.active_connections:
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
        """Fire-and-forget broadcast via asyncio task.

        Used by the batch endpoint so the HTTP response returns immediately
        without waiting for every WebSocket client to acknowledge. Safe to
        call from an async context — creates a background task on the
        running event loop.
        """
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(self.broadcast(message))
        except RuntimeError:
            # No running loop (shouldn't happen in FastAPI, but be safe).
            pass


manager = ConnectionManager()
