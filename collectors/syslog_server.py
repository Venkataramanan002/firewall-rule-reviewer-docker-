import asyncio
import logging
from typing import Dict, Any, Optional
from parsers.paloalto import PaloAltoParser
from parsers.fortinet import FortinetParser
from parsers.cisco import CiscoParser
from parsers.geoip_resolver import GeoIPResolver
from parsers.useragent_parser import UserAgentParser
from utils.deduplicator import Deduplicator
from utils.duration_tracker import DurationTracker
from database.connection import AsyncSessionLocal
from database.operations import insert_connection, insert_threat, insert_admin_audit

logger = logging.getLogger(__name__)

class SyslogServer:
    def __init__(self, host='0.0.0.0', udp_port=514, tcp_port=601):
        self.host = host
        self.udp_port = udp_port
        self.tcp_port = tcp_port
        
        self.pa_parser = PaloAltoParser()
        self.forti_parser = FortinetParser()
        self.cisco_parser = CiscoParser()
        self.geoip = GeoIPResolver()
        self.ua_parser = UserAgentParser()
        self.deduplicator = Deduplicator()
        self.duration_tracker = DurationTracker()

    async def start(self):
        logger.info(f"Starting Syslog Server on {self.host} UDP {self.udp_port} and TCP {self.tcp_port}")
        
        # Start UDP listener
        loop = asyncio.get_running_loop()
        udp_transport, udp_protocol = await loop.create_datagram_endpoint(
            lambda: SyslogUDPProtocol(self),
            local_addr=(self.host, self.udp_port)
        )
        
        # Start TCP listener
        tcp_server = await asyncio.start_server(
            self.handle_tcp_syslog, self.host, self.tcp_port
        )
        
        async with tcp_server:
            await tcp_server.serve_forever()

    async def handle_tcp_syslog(self, reader, writer):
        while True:
            data = await reader.read(8192)
            if not data:
                break
            message = data.decode('utf-8', errors='ignore').strip()
            if message:
                await self.process_log(message, writer.get_extra_info('peername')[0])
        writer.close()

    async def process_log(self, message: str, source_ip: str):
        logger.debug(f"Received log from {source_ip}: {message[:100]}...")
        
        # Determine vendor based on message content or pre-configured source IP mapping
        # For simplicity, we try each parser
        parsed_data = {}
        if 'paloalto' in message.lower() or ',' in message: # Simple heuristic for PA
            parsed_data = self.pa_parser.parse(message)
        elif 'devname=' in message or 'type=traffic' in message:
            parsed_data = self.forti_parser.parse(message)
        elif '%ASA-' in message:
            parsed_data = self.cisco_parser.parse(message)
            
        if not parsed_data:
            return

        # Handle Connection logs
        if parsed_data.get("type") == "connection":
            await self._handle_connection(parsed_data)
        elif parsed_data.get("type") == "threat":
            await self._handle_threat(parsed_data)
        elif parsed_data.get("type") == "admin_audit":
            await self._handle_audit(parsed_data)

    async def _handle_connection(self, data: Dict[str, Any]):
        # Deduplication
        if self.deduplicator.is_duplicate(data['src_ip'], data['dst_ip'], str(data['timestamp'])):
            logger.debug(f"Duplicate log detected, skipping: {data['src_ip']} -> {data['dst_ip']}")
            return

        # GeoIP Resolution
        data['geo_src_country'], data['geo_src_city'] = self.geoip.resolve(data['src_ip'])
        data['geo_dst_country'], data['geo_dst_city'] = self.geoip.resolve(data['dst_ip'])
        
        # User-Agent parsing
        if data.get('user_agent'):
            browser, os = self.ua_parser.parse_ua(data['user_agent'])
            data['device_os'] = os # Prefer parsed OS if available
            
        # Duration calculation
        # Palo Alto specific logic for start/end messages
        if 'start' in data.get('action', '').lower():
            session_id = f"{data['src_ip']}:{data['src_port']}:{data['dst_ip']}:{data['dst_port']}"
            self.duration_tracker.store_start(session_id, data['timestamp'])
        elif 'end' in data.get('action', '').lower() or data.get('duration_seconds') is None:
            session_id = f"{data['src_ip']}:{data['src_port']}:{data['dst_ip']}:{data['dst_port']}"
            duration = self.duration_tracker.calculate_duration(session_id, data['timestamp'])
            if duration is not None:
                data['duration_seconds'] = duration
                data['session_end'] = data['timestamp']

        # Database Insertion
        async with AsyncSessionLocal() as session:
            try:
                # Remove internal type key
                db_data = {k: v for k, v in data.items() if k != 'type'}
                await insert_connection(session, db_data)
                logger.info(f"Inserted connection: {data['src_ip']} -> {data['dst_ip']} ({data['app_name']})")
            except Exception as e:
                logger.error(f"Failed to insert connection: {e}")

    async def _handle_threat(self, data: Dict[str, Any]):
        async with AsyncSessionLocal() as session:
            try:
                db_data = {k: v for k, v in data.items() if k != 'type'}
                await insert_threat(session, db_data)
                logger.warning(f"Inserted threat: {data['threat_name']} from {data['src_ip']}")
            except Exception as e:
                logger.error(f"Failed to insert threat: {e}")

    async def _handle_audit(self, data: Dict[str, Any]):
        async with AsyncSessionLocal() as session:
            try:
                db_data = {k: v for k, v in data.items() if k != 'type'}
                await insert_admin_audit(session, db_data)
                logger.info(f"Inserted admin audit: {data['admin_username']} performed {data['action_type']}")
            except Exception as e:
                logger.error(f"Failed to insert admin audit: {e}")

class SyslogUDPProtocol(asyncio.DatagramProtocol):
    def __init__(self, server):
        self.server = server

    def datagram_received(self, data, addr):
        message = data.decode('utf-8', errors='ignore').strip()
        asyncio.create_task(self.server.process_log(message, addr[0]))
