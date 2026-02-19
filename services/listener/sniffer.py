import asyncio
import os
import time
from loguru import logger
from pkg.models.events import NetworkFlowEvent, Protocol

# Robust Scapy Import
SCAPY_AVAILABLE = False
try:
    from scapy.all import IP, TCP, UDP, DNS, DNSQR
    from scapy.packet import Packet
    SCAPY_AVAILABLE = True
except (ImportError, ModuleNotFoundError):
    logger.warning("Scapy or Npcap not found. Traffic capture will be disabled.")
    # Dummy Packet class to prevent NameError in type hints
    class Packet: pass
    IP = TCP = UDP = DNS = DNSQR = None 
except Exception as e:
    logger.warning(f"Error importing Scapy: {e}")
    SCAPY_AVAILABLE = False
    class Packet: pass
    IP = TCP = UDP = DNS = DNSQR = None

class PacketProcessor:
    def __init__(self, producer):
        self.producer = producer
        self.loop = asyncio.get_event_loop()
        self.packet_count = 0
        if SCAPY_AVAILABLE:
            from scapy.all import conf
            logger.info(f"Using Scapy Interface: {conf.iface}")
        if SCAPY_AVAILABLE:
            from scapy.all import conf
            logger.info(f"Using Scapy Interface: {conf.iface}")

    def process_packet_callback(self, packet: Packet):
        """
        Callback executed by Scapy.
        Extracts L7 metadata (DPI).
        """
        self.packet_count += 1
        if self.packet_count % 50 == 0:
            logger.info(f"Sniffer active: Processed {self.packet_count} packets so far...")

        if not packet.haslayer(IP):
            return

        try:
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
                        # Simple robust check for Host header
                        text = payload[:1024].decode('utf-8', errors='ignore')
                        for line in text.split('\r\n'):
                            if line.lower().startswith('host:'):
                                metadata['host'] = line.split(':', 1)[1].strip()
                                protocol = Protocol.HTTP
                                break
                    except Exception:
                        pass

                # 3. DPI: TLS SNI (Server Name Indication)
                elif dst_port == 443 and payload_len > 0:
                    protocol = Protocol.HTTPS
                    try:
                        # Minimal TLS Client Hello parsing to finding SNI extension
                        # Content Type: Handshake (22 -> 0x16)
                        if payload[0] == 0x16:
                            # Skip record header (5 bytes) + Handshake Header (4 bytes)
                            # Client Random (32 bytes) + Session ID Len (1 byte)
                            # This is complex to do robustly in 10 lines, but we try a heuristic search
                            # SNI extension ID is 0x0000
                            # We can search for the server_name (0x00) extension
                            # For MVP stability, we might use a library or a simplified regex on bytes if possible
                            # But better: just assume HTTPS for now if we can't parse easily without full TLS parser.
                            # Let's try to grab it if simple.
                            pass
                            # TODO: robust SNI parser or use scapy.layers.tls if installed
                    except Exception:
                        pass

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
                return # Ignore ICMP etc for MVP

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

            # Schedule async send
            asyncio.run_coroutine_threadsafe(
                self.producer.publish(
                    os.getenv("SH_KAFKA_TOPIC", "sh.telemetry.traffic.v1"), 
                    event
                ), 
                self.loop
            )

        except Exception as e:
            logger.error(f"Error processing packet: {e}")
