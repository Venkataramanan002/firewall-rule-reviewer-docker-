import redis
import os
import logging
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger(__name__)

class Deduplicator:
    def __init__(self):
        redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
        try:
            self.redis = redis.from_url(redis_url)
            self.redis.ping()
        except Exception as e:
            logger.error(f"Failed to connect to Redis for deduplication: {e}")
            self.redis = None

    def is_duplicate(self, src_ip: str, dst_ip: str, timestamp: str, ttl: int = 300) -> bool:
        """
        Check if a connection log is a duplicate within the given TTL.
        Key format: "conn:{src_ip}:{dst_ip}:{timestamp}"
        """
        if not self.redis:
            return False
            
        key = f"conn:{src_ip}:{dst_ip}:{timestamp}"
        if self.redis.exists(key):
            return True
            
        self.redis.setex(key, ttl, "1")
        return False
