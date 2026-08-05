import sys
import os
import asyncio

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from backend.api.routes import router as api_router
from backend.config import CORS_ORIGINS, LAN_MODE, HOST, PORT
from backend.websocket.manager import manager

app = FastAPI(
    title="ThreatVista API",
    description="Privacy-First Insider Threat Detection Backend",
    version="2.0.0"
)

# CORS origins come from config (env THREATVISTA_CORS_ORIGINS), defaulting to
# the local Vite dev server. Never '*' with credentials.
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    # In LAN mode origins is "*", which browsers only accept when credentials
    # are disabled. The dashboard authenticates with a Bearer header (no
    # cookies), so that is fine.
    allow_credentials=not LAN_MODE,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def read_root():
    return {"message": "ThreatVista Backend Running"}

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            await websocket.send_json({"type": "ack", "message": "connected"})
    except WebSocketDisconnect:
        manager.disconnect(websocket)

app.include_router(api_router, prefix="/api")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host=HOST, port=PORT, reload=True)
