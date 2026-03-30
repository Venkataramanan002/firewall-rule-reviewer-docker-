import asyncio
import logging
import yaml
import time
from pysnmp.hlapi.asyncio import *
from typing import Dict, Any, List
from database.connection import AsyncSessionLocal
from database.operations import insert_system_health
from datetime import datetime

logger = logging.getLogger(__name__)

class SNMPPoller:
    def __init__(self, devices_config_path: str, oids_config_path: str):
        with open(devices_config_path, 'r') as f:
            self.devices = yaml.safe_load(f)['devices']
        with open(oids_config_path, 'r') as f:
            self.oids = yaml.safe_load(f)
        
        self.retry_limit = 3
        self.base_backoff = 2 # seconds

    async def poll_all(self):
        while True:
            tasks = [self.poll_device(device) for device in self.devices]
            await asyncio.gather(*tasks)
            await asyncio.sleep(60) # Poll every minute

    async def poll_device(self, device: Dict[str, Any]):
        hostname = device['hostname']
        ip = device['ip']
        community = device['snmp_community']
        
        logger.info(f"Polling system health for {hostname} ({ip})")
        
        metrics = {
            "device_name": hostname,
            "timestamp": datetime.utcnow()
        }
        
        # Poll CPU, Memory, Sessions
        for metric_name, oid in self.oids['system'].items():
            value = await self._get_snmp_value_with_retry(ip, community, oid)
            metrics[metric_name] = value
            
        # Poll Interface Stats (simplified for one interface in this example)
        for metric_name, oid in self.oids['interfaces'].items():
            # For brevity, we poll index .1
            value = await self._get_snmp_value_with_retry(ip, community, f"{oid}.1")
            metrics[metric_name] = value

        # Save to DB
        async with AsyncSessionLocal() as session:
            try:
                await insert_system_health(session, metrics)
                logger.debug(f"Saved system health for {hostname}")
            except Exception as e:
                logger.error(f"Failed to save system health for {hostname}: {e}")

    async def _get_snmp_value_with_retry(self, ip: str, community: str, oid: str):
        for attempt in range(self.retry_limit):
            try:
                errorIndication, errorStatus, errorIndex, varBinds = await getCmd(
                    SnmpEngine(),
                    CommunityData(community),
                    UdpTransportTarget((ip, 161), timeout=2, retries=0),
                    ContextData(),
                    ObjectType(ObjectIdentity(oid))
                )

                if errorIndication:
                    raise Exception(f"SNMP Error: {errorIndication}")
                elif errorStatus:
                    raise Exception(f"SNMP Error Status: {errorStatus.prettyPrint()}")
                else:
                    # Successfully got value
                    for varBind in varBinds:
                        return float(varBind[1]) if hasattr(varBind[1], '__float__') else str(varBind[1])
            
            except Exception as e:
                wait_time = self.base_backoff ** (attempt + 1)
                logger.warning(f"SNMP poll attempt {attempt+1} failed for {ip} OID {oid}: {e}. Retrying in {wait_time}s...")
                await asyncio.sleep(wait_time)
        
        logger.error(f"Failed to poll {ip} OID {oid} after {self.retry_limit} attempts. Device may be offline.")
        return None
