import aiohttp
import os
import logging
import xml.etree.ElementTree as ET
from typing import Dict, Any, Optional
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger(__name__)

class PaloAltoAPIClient:
    def __init__(self):
        self.api_key = os.getenv("PA_API_KEY")
        self.base_url = None # Will be set per device or panorama
        self.app_cache = {} # app_name -> app_category

    async def get_app_categories(self, host: str) -> Dict[str, str]:
        """
        Calls /api/?type=op&cmd=<show>running app-cache
        Parses XML for app -> category mapping.
        """
        url = f"https://{host}/api/?type=op&cmd=<show><running><app-cache></app-cache></running></show>&key={self.api_key}"
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, ssl=False) as response:
                    if response.status == 200:
                        xml_content = await response.text()
                        root = ET.fromstring(xml_content)
                        # Example parsing logic (adjust based on actual PA XML schema)
                        for entry in root.findall(".//entry"):
                            name = entry.find('name').text
                            category = entry.find('category').text
                            self.app_cache[name] = category
                        return self.app_cache
                    else:
                        logger.error(f"PA API error: {response.status}")
        except Exception as e:
            logger.error(f"Failed to fetch app categories from {host}: {e}")
        return {}

    async def get_nat_mappings(self, host: str) -> Dict[str, Any]:
        """
        Calls /api/?type=op&cmd=<show>session all
        To extract NAT mappings.
        """
        url = f"https://{host}/api/?type=op&cmd=<show><session><all></all></session></show>&key={self.api_key}"
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, ssl=False) as response:
                    if response.status == 200:
                        xml_content = await response.text()
                        # Parse NAT mappings from XML
                        # ...
                        return {} # Simplified
        except Exception as e:
            logger.error(f"Failed to fetch NAT mappings from {host}: {e}")
        return {}

    def get_category_for_app(self, app_name: str) -> Optional[str]:
        return self.app_cache.get(app_name)
