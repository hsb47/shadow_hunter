"""
Realistic Traffic Simulator for Shadow Hunter Demo Mode.

Simulates a small corporate office (5 employees) with human-like browsing 
patterns. Each employee has a role, normal browsing habits, and a probability
of sneaking in unauthorized AI tool usage.
"""
import asyncio
import random
from datetime import datetime
from loguru import logger
from pkg.models.events import NetworkFlowEvent, Protocol


# ─── Employee Personas ───────────────────────────────────────────────
EMPLOYEES = [
    {
        "name": "Dev_Ravi",
        "ip": "192.168.1.10",
        "role": "developer",
        "normal_sites": [
            "github.com", "stackoverflow.com", "npmjs.com", 
            "docs.python.org", "developer.mozilla.org", "pypi.org"
        ],
        "ai_temptation": 0.15,  # 15% chance per cycle to sneak AI usage
        "preferred_ai": ["copilot.microsoft.com", "cursor.sh", "chatgpt.com"],
    },
    {
        "name": "Designer_Priya",
        "ip": "192.168.1.11",
        "role": "designer",
        "normal_sites": [
            "figma.com", "dribbble.com", "behance.net",
            "fonts.google.com", "unsplash.com", "coolors.co"
        ],
        "ai_temptation": 0.12,
        "preferred_ai": ["midjourney.com", "leonardo.ai", "canva.com"],
    },
    {
        "name": "Manager_Arjun",
        "ip": "192.168.1.12",
        "role": "manager",
        "normal_sites": [
            "mail.google.com", "calendar.google.com", "slack.com",
            "zoom.us", "docs.google.com", "notion.so"
        ],
        "ai_temptation": 0.08,
        "preferred_ai": ["chatgpt.com", "gemini.google.com"],
    },
    {
        "name": "DataSci_Meera",
        "ip": "192.168.1.13",
        "role": "data_scientist",
        "normal_sites": [
            "kaggle.com", "jupyter.org", "pandas.pydata.org",
            "scikit-learn.org", "arxiv.org", "paperswithcode.com"
        ],
        "ai_temptation": 0.25,  # Data scientists LOVE AI tools
        "preferred_ai": ["huggingface.co", "api.openai.com", "anthropic.com", "chat.deepseek.com"],
    },
    {
        "name": "Intern_Kiran",
        "ip": "192.168.1.14",
        "role": "intern",
        "normal_sites": [
            "google.com", "youtube.com", "reddit.com",
            "medium.com", "w3schools.com", "geeksforgeeks.org"
        ],
        "ai_temptation": 0.30,  # Interns use AI the most
        "preferred_ai": ["chatgpt.com", "claude.ai", "perplexity.ai", "gemini.google.com"],
    },
]

# Internal servers that employees talk to
INTERNAL_SERVERS = [
    {"ip": "192.168.1.100", "name": "file-server", "port": 445},
    {"ip": "192.168.1.101", "name": "git-server", "port": 22},
    {"ip": "192.168.1.102", "name": "jira-server", "port": 8080},
    {"ip": "192.168.1.200", "name": "db-server", "port": 5432},
]


class TrafficGenerator:
    """
    Simulates realistic corporate network traffic with human-like patterns.
    """
    def __init__(self, broker):
        self.broker = broker
        self.running = False
        self.cycle = 0

    async def start(self):
        self.running = True
        logger.info("🏢 Corporate Traffic Simulator ACTIVE")
        logger.info(f"   Simulating {len(EMPLOYEES)} employees:")
        for emp in EMPLOYEES:
            logger.info(f"   • {emp['name']} ({emp['role']}) @ {emp['ip']}")
        
        while self.running:
            try:
                self.cycle += 1
                
                # Each cycle, simulate activity for each employee
                for employee in EMPLOYEES:
                    await self._simulate_employee(employee)
                
                # Occasional internal server-to-server traffic (background noise)
                if random.random() > 0.5:
                    await self._send_internal_server_traffic()
                
                # Human-like pacing: 2-5 seconds between activity bursts
                await asyncio.sleep(random.uniform(2.0, 5.0))
                
            except Exception as e:
                logger.error(f"Simulator error: {e}")
                await asyncio.sleep(2)

    async def stop(self):
        self.running = False

    async def _simulate_employee(self, emp: dict):
        """Simulate one employee's activity in a single cycle."""
        
        # Not every employee is active every cycle (realistic idle periods)
        if random.random() > 0.6:
            return  # Employee is idle (reading, in a meeting, etc.)
        
        # 1. Normal browsing (most common activity)
        site = random.choice(emp["normal_sites"])
        await self._send_web_traffic(emp["ip"], site)
        
        # 2. Maybe access internal resources
        if random.random() > 0.7:
            server = random.choice(INTERNAL_SERVERS)
            await self._send_internal_traffic(emp["ip"], server)
        
        # 3. The sneaky part: unauthorized AI usage
        if random.random() < emp["ai_temptation"]:
            ai_service = random.choice(emp["preferred_ai"])
            # AI requests tend to have larger payloads (sending prompts, receiving responses)
            await self._send_ai_traffic(emp["ip"], ai_service)

    async def _send_web_traffic(self, src_ip: str, domain: str):
        """Normal HTTPS web browsing."""
        event = NetworkFlowEvent(
            source_ip=src_ip,
            source_port=random.randint(49152, 65535),
            destination_ip="1.1.1.1",
            destination_port=443,
            protocol=Protocol.HTTPS,
            bytes_sent=random.randint(200, 3000),
            bytes_received=random.randint(5000, 50000),
            metadata={"host": domain, "sni": domain}
        )
        await self.broker.publish("sh.telemetry.traffic.v1", event)

    async def _send_internal_traffic(self, src_ip: str, server: dict):
        """Internal server access (file shares, databases, etc.)."""
        event = NetworkFlowEvent(
            source_ip=src_ip,
            source_port=random.randint(49152, 65535),
            destination_ip=server["ip"],
            destination_port=server["port"],
            protocol=Protocol.TCP,
            bytes_sent=random.randint(100, 2000),
            metadata={}
        )
        await self.broker.publish("sh.telemetry.traffic.v1", event)

    async def _send_ai_traffic(self, src_ip: str, ai_domain: str):
        """Shadow AI usage — larger payloads, HTTPS to known AI domains."""
        # AI traffic typically involves larger request/response payloads
        event = NetworkFlowEvent(
            source_ip=src_ip,
            source_port=random.randint(49152, 65535),
            destination_ip="8.8.8.8",
            destination_port=443,
            protocol=Protocol.HTTPS,
            bytes_sent=random.randint(5000, 80000),   # Large prompts
            bytes_received=random.randint(10000, 200000),  # Large responses
            metadata={"host": ai_domain, "sni": ai_domain}
        )
        await self.broker.publish("sh.telemetry.traffic.v1", event)

    async def _send_internal_server_traffic(self):
        """Background noise: server-to-server communication."""
        s1, s2 = random.sample(INTERNAL_SERVERS, 2)
        event = NetworkFlowEvent(
            source_ip=s1["ip"],
            source_port=random.randint(49152, 65535),
            destination_ip=s2["ip"],
            destination_port=s2["port"],
            protocol=Protocol.TCP,
            bytes_sent=random.randint(50, 500),
            metadata={}
        )
        await self.broker.publish("sh.telemetry.traffic.v1", event)
