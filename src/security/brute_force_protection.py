import os
from src.security.base import BaseSecurityPlugin

class BruteForcePlugin(BaseSecurityPlugin):
    """Detect simple brute-force attacks on session codes."""
    
    def __init__(self, limit=None):
        super().__init__('BRUTE_FORCE_PROTECTION')
        self.limit = limit if limit is not None else int(os.getenv('BRUTE_FORCE_LIMIT', '10'))
        
    def inspect(self, req, ip, access_log):
        # Count unique codes accessed in recent history (last 60s)
        # access_log structure: [{'timestamp':..., 'action':..., 'code':...}, ...]
        
        codes = set()
        for entry in access_log:
            code = entry.get('code')
            if code:
                codes.add(code)
                       
        if len(codes) >= self.limit:
            return True, "Brute Force Attempt", {"limit": self.limit, "detected": len(codes), "violation": "BRUTE_FORCE"}
            
        return False, None, None
