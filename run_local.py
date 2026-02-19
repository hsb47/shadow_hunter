"""
Shadow Hunter — Local Monolith Entry Point

Usage:
  python run_local.py          → DEMO MODE (simulated traffic, no Npcap needed)
  python run_local.py --live   → LIVE MODE (real packet capture, requires Npcap)
"""
import asyncio
import sys
import uvicorn
import os
from loguru import logger

from pkg.infra.local.broker import MemoryBroker
from pkg.infra.local.store import NetworkXStore
from services.analyzer.engine import AnalyzerEngine
from services.listener.main import ListenerService
from services.api.main import app as api_app, set_live_mode
from services.api.dependencies import set_graph_store
from services.listener.sniffer import SCAPY_AVAILABLE

# Configuration
LIVE_MODE = "--live" in sys.argv

async def main():
    mode_label = "LIVE" if LIVE_MODE else "DEMO"
    logger.info(f"Starting Shadow Hunter in {mode_label} mode...")
    set_live_mode(LIVE_MODE)
    
    # 1. Initialize Shared Infrastructure
    broker = MemoryBroker()
    store = NetworkXStore()
    
    await broker.start()
    set_graph_store(store)
    
    # 2. Initialize Services
    analyzer = AnalyzerEngine(broker, store)
    await analyzer.start()

    # 3. Mode-specific startup
    simulator_task = None

    if LIVE_MODE:
        # ═══ LIVE MODE: Real packet capture ═══
        if not SCAPY_AVAILABLE:
            logger.error("=" * 60)
            logger.error("❌ LIVE MODE requires Npcap!")
            logger.error("   Download: https://npcap.com/#download")
            logger.error("   Install it, then restart.")
            logger.error("   Or run without --live for demo mode.")
            logger.error("=" * 60)
            return
        
        listener = ListenerService(broker=broker)
        await listener.start()
        logger.info("🔴 LIVE MODE: Capturing real network packets")
    else:
        # ═══ DEMO MODE: Simulated corporate traffic ═══
        logger.info("=" * 60)
        logger.info("🟢 DEMO MODE: Simulated corporate traffic")
        logger.info("   5 virtual employees generating realistic activity")
        logger.info("   AI alerts will appear when they 'sneak' AI usage")
        logger.info("   Run with --live flag for real packet capture")
        logger.info("=" * 60)
        from services.simulator.traffic_generator import TrafficGenerator
        sim = TrafficGenerator(broker)
        simulator_task = asyncio.create_task(sim.start())

    # 4. Start API Server
    # Cloud Run injects PORT env variable (default 8080); fallback to 8000 for local dev
    port = int(os.environ.get("PORT", 8000))
    config = uvicorn.Config(api_app, host="0.0.0.0", port=port, log_level="info")
    server = uvicorn.Server(config)
    
    logger.info("Dashboard: http://localhost:5173")
    logger.info("API: http://localhost:8000/docs")
    logger.info("Press Ctrl+C to stop.")
    
    try:
        await server.serve()
    except asyncio.CancelledError:
        pass
    except Exception as e:
        logger.error(f"🔥 Error in server.serve(): {e}")
    finally:
        logger.info("Shutting down...")
        if simulator_task:
            simulator_task.cancel()
        await broker.stop()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
    except Exception as e:
        logger.exception(f"CRITICAL ERROR: {e}")
        sys.exit(1)
