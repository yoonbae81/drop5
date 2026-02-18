import time
import os
from src.security.base import BaseSecurityPlugin
from src.config import BLOCKED_UA_FILE

class UABlockerPlugin(BaseSecurityPlugin):
    """Plugins that inspect User-Agents for known malicious patterns."""
    
    def __init__(self):
        super().__init__('USER_AGENT_BLOCKER')
        self.ua_file = BLOCKED_UA_FILE
        self.blocked_uas = set()
        self.last_sync = time.time()
        self._load_uas()
        
    def _load_uas(self):
        if os.path.exists(self.ua_file):
            try:
                with open(self.ua_file, 'r') as f:
                    self.blocked_uas = set(line.strip().lower() for line in f 
                                          if line.strip() and not line.startswith('#'))
            except:
                pass

    def check_immediate(self, req, ip):
        """Check User-Agent immediately."""
        now = time.time()
        # Periodically refresh
        if now - self.last_sync > 60:
            self._load_uas()
            self.last_sync = now
            
        ua = req.get_header('User-Agent', '').lower()
        if ua and any(pattern in ua for pattern in self.blocked_uas):
            return True, "Blacklisted User-Agent", {"ua": ua}
            
        return False, None, None

    def inspect(self, req, ip, access_log):
        # Already checked in check_immediate
        return False, None, None
