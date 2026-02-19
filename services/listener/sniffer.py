"""
Packet Processor — Captures and processes network packets using Scapy.

Performance Optimizations:
  - Decoupled capture from processing via asyncio.Queue buffer.
  - DPI runs in a separate consumer task, preventing packet loss.
  - Robust TLS SNI extraction replaces the former placeholder.
"""
import asyncio
import os
import struct
import time
from loguru import logger
from pkg.models.events import NetworkFlowEvent, Protocol

# ── Robust Scapy Import ──
SCAPY_AVAILABLE = False
try:
    from scapy.all import IP, TCP, UDP, DNS, DNSQR
    from scapy.packet import Packet
    SCAPY_AVAILABLE = True
except (ImportError, ModuleNotFoundError):
    logger.warning("Scapy or Npcap not found. Traffic capture will be disabled.")
    class Packet: pass
    IP = TCP = UDP = DNS = DNSQR = None
except Exception as e:
    logger.warning(f"Error importing Scapy: {e}")
    SCAPY_AVAILABLE = False
    class Packet: pass
    IP = TCP = UDP = DNS = DNSQR = None


def extract_tls_sni(payload: bytes) -> str | None:
    """
    Parse TLS Client Hello to extract the SNI (Server Name Indication).
    
    TLS Record:  [ContentType(1) | Version(2) | Length(2)] = 5 bytes
    Handshake:   [Type(1) | Length(3) | Version(2) | Random(32) | ...] 
    We skip Session ID, Cipher Suites, Compression, then walk Extensions
    looking for extension type 0x0000 (server_name).
    """
    try:
        if len(payload) < 5 or payload[0] != 0x16:  # Not a Handshake
            return None

        # Skip TLS record header (5 bytes)
        pos = 5
        if pos >= len(payload) or payload[pos] != 0x01:  # Not Client Hello
            return None

        # Skip Handshake header: Type(1) + Length(3) + Version(2) + Random(32)
        pos += 1 + 3 + 2 + 32
        if pos >= len(payload):
            return None

        # Skip Session ID
        session_id_len = payload[pos]
        pos += 1 + session_id_len
        if pos + 2 > len(payload):
            return None

        # Skip Cipher Suites
        cipher_suites_len = struct.unpack("!H", payload[pos:pos + 2])[0]
        pos += 2 + cipher_suites_len
        if pos + 1 > len(payload):
            return None

        # Skip Compression Methods
        compression_len = payload[pos]
        pos += 1 + compression_len
        if pos + 2 > len(payload):
            return None

        # Extensions Length
        extensions_len = struct.unpack("!H", payload[pos:pos + 2])[0]
        pos += 2
        extensions_end = pos + extensions_len

        # Walk extensions
        while pos + 4 <= extensions_end and pos + 4 <= len(payload):
            ext_type = struct.unpack("!H", payload[pos:pos + 2])[0]
            ext_len = struct.unpack("!H", payload[pos + 2:pos + 4])[0]
            pos += 4

            if ext_type == 0x0000:  # server_name extension
                # ServerNameList: Length(2) + Type(1) + NameLen(2) + Name
                if pos + 5 <= len(payload):
                    name_len = struct.unpack("!H", payload[pos + 3:pos + 5])[0]
                    if pos + 5 + name_len <= len(payload):
                        return payload[pos + 5:pos + 5 + name_len].decode("ascii", errors="ignore")
                return None

            pos += ext_len

    except (struct.error, IndexError, ValueError):
        pass

    return None


class PacketProcessor:
    """
    Processes network packets with a buffered architecture:
      1. Scapy callback pushes raw packets to an asyncio.Queue (fast, non-blocking).
      2. A consumer coroutine drains the queue, runs DPI, and publishes events.
    """

    def __init__(self, producer, buffer_size: int = 1000):
        self.producer = producer
        self.loop = asyncio.get_event_loop()
        self.packet_count = 0
        self._queue: asyncio.Queue = asyncio.Queue(maxsize=buffer_size)
        self._dropped = 0

        if SCAPY_AVAILABLE:
            from scapy.all import conf
            logger.info(f"Using Scapy Interface: {conf.iface}")
            # Start the consumer task
            self.loop.create_task(self._process_queue())

    # ── Producer (called by Scapy sniff thread) ──

    def process_packet_callback(self, packet: Packet):
        """
        Scapy callback — runs in the sniff thread.
        Pushes packets to the async queue as fast as possible.
        """
        self.packet_count += 1
        if self.packet_count % 50 == 0:
            dropped_info = f" (dropped: {self._dropped})" if self._dropped else ""
            logger.info(f"Sniffer active: {self.packet_count} packets captured{dropped_info}")

        if not packet.haslayer(IP):
            return

        try:
            self._queue.put_nowait(packet)
        except asyncio.QueueFull:
            self._dropped += 1

    # ── Consumer (async coroutine) ──

    async def _process_queue(self):
        """Drain the packet queue and process each packet with full DPI."""
        logger.info("Packet consumer started — draining buffer...")
        while True:
            packet = await self._queue.get()
            try:
                await self._process_single(packet)
            except Exception as e:
                logger.error(f"Error processing packet: {e}")

    async def _process_single(self, packet):
        """Full DPI processing on a single packet."""
        ip_layer = packet[IP]
        protocol = None
        src_port = 0
        dst_port = 0
        payload_len = 0
        metadata = {}

        # 1. Determine L4 Protocol & Ports
        if packet.haslayer(TCP):
            layer = packet[TCP]
            protocol = Protocol.TCP
            src_port = layer.sport
            dst_port = layer.dport
            payload = bytes(layer.payload)
            payload_len = len(payload)

            # 2. DPI: HTTP Host Header
            if dst_port == 80 and payload_len > 0:
                try:
                    text = payload[:1024].decode('utf-8', errors='ignore')
                    for line in text.split('\r\n'):
                        if line.lower().startswith('host:'):
                            metadata['host'] = line.split(':', 1)[1].strip()
                            protocol = Protocol.HTTP
                            break
                except Exception:
                    pass

            # 3. DPI: TLS SNI (robust parser)
            elif dst_port == 443 and payload_len > 0:
                protocol = Protocol.HTTPS
                sni = extract_tls_sni(payload)
                if sni:
                    metadata['sni'] = sni

        elif packet.haslayer(UDP):
            layer = packet[UDP]
            protocol = Protocol.UDP
            src_port = layer.sport
            dst_port = layer.dport
            payload_len = len(layer.payload)

            # 4. DPI: DNS Query
            if packet.haslayer("DNS") and packet.haslayer("DNSQR"):
                try:
                    query = packet["DNSQR"].qname.decode('utf-8').rstrip('.')
                    metadata['dns_query'] = query
                    protocol = Protocol.DNS
                except Exception:
                    pass
        else:
            return  # Ignore ICMP etc for MVP

        if not protocol:
            return

        event = NetworkFlowEvent(
            source_ip=ip_layer.src,
            source_port=src_port,
            destination_ip=ip_layer.dst,
            destination_port=dst_port,
            protocol=protocol,
            bytes_sent=payload_len,
            bytes_received=0,
            metadata=metadata
        )

        await self.producer.publish(
            os.getenv("SH_KAFKA_TOPIC", "sh.telemetry.traffic.v1"),
            event
        )
