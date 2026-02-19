from fastapi import WebSocket
from typing import List
import json
from loguru import logger

class ConnectionManager:
    """
    Manages active WebSocket connections for real-time updates.
    """
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(f"WebSocket client connected. Total clients: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            logger.info(f"WebSocket client disconnected. Total clients: {len(self.active_connections)}")

    async def broadcast(self, message: dict):
        """
        Broadcast a JSON message to all connected clients.
        Silently handles disconnected clients by removing them.
        """
        if not self.active_connections:
            return

        payload = json.dumps(message)
        cleanup_list = []
        
        for connection in self.active_connections:
            try:
                await connection.send_text(payload)
            except Exception as e:
                logger.warning(f"Failed to send to client, removing: {e}")
                cleanup_list.append(connection)
        
        for dead_ws in cleanup_list:
            self.disconnect(dead_ws)

# Global instance
manager = ConnectionManager()
