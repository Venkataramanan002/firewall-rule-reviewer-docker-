from user_agents import parse
from typing import Tuple, Optional
import logging

logger = logging.getLogger(__name__)

class UserAgentParser:
    def __init__(self):
        pass

    def parse_ua(self, ua_string: str) -> Tuple[Optional[str], Optional[str]]:
        """
        Parses user agent string into (browser, os).
        Returns (None, None) if parsing fails or string is empty.
        """
        if not ua_string:
            return None, None
            
        try:
            ua = parse(ua_string)
            browser = f"{ua.browser.family} {ua.browser.version_string}"
            os = f"{ua.os.family} {ua.os.version_string}"
            
            return browser, os
        except Exception as e:
            logger.error(f"Error parsing user agent {ua_string}: {e}")
            return None, None
