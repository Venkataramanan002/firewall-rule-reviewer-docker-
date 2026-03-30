import redis
import os
import logging
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger(__name__)

class DurationTracker:
    def __init__(self):
        redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
        try:
            self.redis = redis.from_url(redis_url)
            self.redis.ping()
        except Exception as e:
            logger.error(f"Failed to connect to Redis for duration tracking: {e}")
            self.redis = None

    def store_start(self, connection_id: str, timestamp: datetime):
        """
        Store the start timestamp for a session.
        """
        if not self.redis:
            return
            
        key = f"session:{connection_id}"
        self.redis.setex(key, 86400, timestamp.isoformat()) # 1 day TTL

    def calculate_duration(self, connection_id: str, end_timestamp: datetime) -> int:
        """
        Get start timestamp, calculate duration, and delete key.
        Returns duration in seconds.
        """
        if not self.redis:
            return None
            
        key = f"session:{connection_id}"
        start_iso = self.redis.get(key)
        
        if not start_iso:
            return None
            
        self.redis.delete(key)
        start_timestamp = datetime.fromisoformat(start_iso.decode())
        
        duration = int((end_timestamp - start_timestamp).total_seconds())
        return duration if duration >= 0 else 0
