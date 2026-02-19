import os
from fastapi import FastAPI, WebSocket, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from loguru import logger
from contextlib import asynccontextmanager

from services.api.routers import discovery, policy

# Module-level mode flag (set by run_local.py)
_live_mode = False

def set_live_mode(val: bool):
    global _live_mode
    _live_mode = val

def get_live_mode() -> bool:
    return _live_mode

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Control Plane API starting...")
    yield
    logger.info("Control Plane API shutting down...")

app = FastAPI(
    title="Shadow Hunter Control Plane",
    version="0.1.0",
    description="API for managing Shadow Hunter security platform",
    lifespan=lifespan
)

# Enable CORS for dashboard
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(discovery.router, prefix="/v1/discovery", tags=["Discovery"])
app.include_router(policy.router, prefix="/v1/policy", tags=["Policy"])

# ── API Key Authentication Middleware ──
# Protects write operations. Read endpoints remain open.
API_KEY = os.environ.get("SH_API_KEY", "shadow-hunter-dev")
OPEN_PATHS = {"/health", "/ws", "/docs", "/openapi.json", "/redoc"}

@app.middleware("http")
async def api_key_auth(request: Request, call_next):
    # Allow all GET requests and open paths
    if request.method == "GET" or request.url.path in OPEN_PATHS:
        return await call_next(request)

    # Require API key for write operations
    key = request.headers.get("X-API-Key")
    if key != API_KEY:
        return JSONResponse(
            status_code=401,
            content={"detail": "Invalid or missing API key. Set X-API-Key header."}
        )
    return await call_next(request)

@app.get("/health")
async def health_check():
    return {"status": "ok", "component": "control-plane"}

@app.get("/v1/status")
async def system_status():
    return {"mode": "live" if _live_mode else "demo"}

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    from services.api.transceiver import manager
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except Exception:
        manager.disconnect(websocket)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
