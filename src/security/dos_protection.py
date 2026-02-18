import os
import time
from src.security.base import BaseSecurityPlugin

class DosProtectionPlugin(BaseSecurityPlugin):
    """
    Advanced DoS protection using behavioral analysis.
    This module contains sensitive logic for detecting and blocking volumetric attacks.
    """
    
    def __init__(self):
        super().__init__('DOS_PROTECTION')
        self.request_limit = int(os.getenv('GLOBAL_REQUEST_LIMIT', '100'))
        self.upload_limit = int(os.getenv('UPLOAD_REQUEST_LIMIT', '10'))
        self.min_upload_delay = float(os.getenv('MIN_UPLOAD_DELAY', '1.5'))
        # Store first seen time for IP+Client combination for instant upload detection
        self.first_seen = {} # {(ip, client_id): timestamp}

    def inspect(self, req, ip, access_log):
        now = time.time()
        
        # Current action
        current_action = None
        if hasattr(req, 'json') and req.json:
            current_action = req.json.get('action') # If applicable
        if not current_action and 'upload' in req.path.lower():
            current_action = 'UPLOAD'
            
        # 1. Volumetric Attack (Too many requests)
        # We check the count of logs in the recent window (last 60s)
        req_count = len(access_log)
        
        # Check authentication (Client ID presence)
        client_id = None
        if req.json: client_id = req.json.get('clientId')
        if not client_id: client_id = req.forms.get('clientId') or req.query.get('clientId')
        
        if not client_id:
            # Stricter limits for anonymous/unidentified traffic
            if req_count > 60:
                return True, "Anonymous Volumetric Attack", {"limit": 60, "count": req_count, "violation": "VOLUME"}
            
            # Check specific actions like session creation
            sessions = len([e for e in access_log if e.get('action') == 'CREATE_SESSION'])
            if sessions > 5:
                # We limit session creation spikes
                if current_action == 'CREATE_SESSION':
                    return True, "Bot Session Spike", {"limit": 5, "count": sessions, "violation": "SESSION_SPIKE"}
        else:
            # Trace first seen time
            key = (ip, client_id)
            if key not in self.first_seen:
                self.first_seen[key] = now
            
            # Authenticated users get higher limits
            if req_count > self.request_limit:
                return True, "Aggressive Request Spike", {"limit": self.request_limit, "count": req_count, "violation": "SPIKE"}

        # 2. Fast-Action / Upload Protection
        if current_action == 'UPLOAD':
            # Instant upload check (machine speed) using tracked first_seen
            if client_id:
                 start_time = self.first_seen.get((ip, client_id))
                 if start_time and (now - start_time) < self.min_upload_delay:
                     return True, "Bot Behavior (Instant Upload)", {"delay": now - start_time, "violation": "INSTANT_UPLOAD"}
            
            # Upload frequency check
            uploads = len([e for e in access_log if e.get('action') == 'UPLOAD'])
            if uploads > self.upload_limit:
                return True, "Upload Flood Detected", {"limit": self.upload_limit, "count": uploads, "violation": "UPLOAD_FLOOD"}
                
        # 3. Cleanup old first_seen data
        if len(self.first_seen) > 1000: # Simple limit to prevent memory leak
             self.first_seen = {k: v for k, v in self.first_seen.items() if now - v < 600}
             
        return False, None, None
