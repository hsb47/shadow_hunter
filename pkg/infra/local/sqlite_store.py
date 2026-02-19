"""
SQLite Graph Store — Persistent graph storage using SQLite via aiosqlite.

Replaces the in-memory NetworkXStore with a disk-backed store that survives
process restarts. Ideal for long-term monitoring and historical analysis.

Usage:
    store = SQLiteGraphStore("shadow_hunter.db")
    await store.initialize()
    await store.add_node("192.168.1.10", ["Node"], {"type": "internal"})
"""
import json
import aiosqlite
from typing import List, Dict, Any
from pkg.core.interfaces import GraphStore
from loguru import logger


class SQLiteGraphStore(GraphStore):
    """
    Persistent graph store backed by SQLite.

    Schema:
    - nodes: id (PK), labels (JSON), properties (JSON)
    - edges: source, target, relation, properties (JSON)
      Composite PK on (source, target, relation)
    """

    def __init__(self, db_path: str = "shadow_hunter.db"):
        self.db_path = db_path
        self._db: aiosqlite.Connection | None = None

    async def initialize(self):
        """Create tables if they don't exist and open the connection."""
        self._db = await aiosqlite.connect(self.db_path)
        # WAL mode for better concurrent read/write performance
        await self._db.execute("PRAGMA journal_mode=WAL")
        await self._db.execute("PRAGMA synchronous=NORMAL")

        await self._db.execute("""
            CREATE TABLE IF NOT EXISTS nodes (
                id TEXT PRIMARY KEY,
                labels TEXT NOT NULL DEFAULT '[]',
                properties TEXT NOT NULL DEFAULT '{}'
            )
        """)
        await self._db.execute("""
            CREATE TABLE IF NOT EXISTS edges (
                source TEXT NOT NULL,
                target TEXT NOT NULL,
                relation TEXT NOT NULL,
                properties TEXT NOT NULL DEFAULT '{}',
                PRIMARY KEY (source, target, relation)
            )
        """)
        await self._db.execute("""
            CREATE INDEX IF NOT EXISTS idx_edges_source ON edges(source)
        """)
        await self._db.execute("""
            CREATE INDEX IF NOT EXISTS idx_edges_target ON edges(target)
        """)
        await self._db.commit()
        logger.info(f"📦 SQLite Graph Store initialized at {self.db_path}")

    async def add_node(self, node_id: str, labels: List[str], properties: Dict[str, Any]):
        """Insert or update a node (upsert)."""
        # Check if node exists for label merging
        async with self._db.execute(
            "SELECT labels, properties FROM nodes WHERE id = ?", (node_id,)
        ) as cursor:
            row = await cursor.fetchone()

        if row:
            existing_labels = json.loads(row[0])
            existing_props = json.loads(row[1])
            merged_labels = list(set(existing_labels + labels))
            existing_props.update(properties)
            await self._db.execute(
                "UPDATE nodes SET labels = ?, properties = ? WHERE id = ?",
                (json.dumps(merged_labels), json.dumps(existing_props), node_id)
            )
        else:
            await self._db.execute(
                "INSERT INTO nodes (id, labels, properties) VALUES (?, ?, ?)",
                (node_id, json.dumps(labels), json.dumps(properties))
            )
        await self._db.commit()

    async def add_edge(self, source_id: str, target_id: str, relation_type: str, properties: Dict[str, Any]):
        """Insert or update an edge (upsert)."""
        # Ensure both nodes exist
        for nid in (source_id, target_id):
            async with self._db.execute(
                "SELECT 1 FROM nodes WHERE id = ?", (nid,)
            ) as cursor:
                if not await cursor.fetchone():
                    await self.add_node(nid, ["Unknown"], {})

        await self._db.execute(
            """INSERT INTO edges (source, target, relation, properties)
               VALUES (?, ?, ?, ?)
               ON CONFLICT(source, target, relation)
               DO UPDATE SET properties = ?""",
            (source_id, target_id, relation_type,
             json.dumps(properties), json.dumps(properties))
        )
        await self._db.commit()

    async def get_all_nodes(self) -> List[Dict[str, Any]]:
        """Retrieve all nodes."""
        nodes = []
        async with self._db.execute("SELECT id, labels, properties FROM nodes") as cursor:
            async for row in cursor:
                props = json.loads(row[2])
                props["id"] = row[0]
                props["labels"] = json.loads(row[1])
                nodes.append(props)
        return nodes

    async def get_all_edges(self) -> List[Dict[str, Any]]:
        """Retrieve all edges."""
        edges = []
        async with self._db.execute(
            "SELECT source, target, relation, properties FROM edges"
        ) as cursor:
            async for row in cursor:
                props = json.loads(row[3])
                props["source"] = row[0]
                props["target"] = row[1]
                props["relation"] = row[2]
                edges.append(props)
        return edges

    async def close(self):
        """Close the database connection."""
        if self._db:
            await self._db.close()
            logger.info("SQLite Graph Store closed.")
