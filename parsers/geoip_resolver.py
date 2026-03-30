import maxminddb
import os
import logging
from typing import Tuple, Optional

logger = logging.getLogger(__name__)

class GeoIPResolver:
    def __init__(self, db_path: str = 'data/GeoLite2-City.mmdb'):
        self.reader = None
        if os.path.exists(db_path):
            try:
                self.reader = maxminddb.open_database(db_path)
                logger.info(f"GeoIP database loaded from {db_path}")
            except Exception as e:
                logger.error(f"Failed to load GeoIP database: {e}")
        else:
            logger.warning(f"GeoIP database not found at {db_path}. Geolocation will be disabled.")

    def resolve(self, ip: str) -> Tuple[Optional[str], Optional[str]]:
        """
        Resolves IP to (country, city).
        Returns (None, None) if not found or reader is not initialized.
        """
        if not self.reader:
            return None, None
            
        try:
            response = self.reader.get(ip)
            if not response:
                return None, None
            
            country = response.get('country', {}).get('names', {}).get('en')
            city = response.get('city', {}).get('names', {}).get('en')
            
            return country, city
        except Exception as e:
            logger.error(f"Error resolving IP {ip}: {e}")
            return None, None

    def close(self):
        if self.reader:
            self.reader.close()
