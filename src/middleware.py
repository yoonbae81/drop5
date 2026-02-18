import time
import os
import ipaddress
import platform
from bottle import request, abort
import json
from src.config import TRUSTED_PROXIES, BLOCKED_UA_FILE, DEBUG

class SecurityMiddleware:
    def __init__(self, limit=None, logger_func=None):
        """
        Initialize security middleware. 
        Detection is logged for fail2ban to handle OS-level blocking.
        """
        self.logger_func = logger_func
        self.is_dev = DEBUG
        
        # --- Limits ---
        self.code_limit = limit if limit is not None else int(os.getenv('BRUTE_FORCE_LIMIT', '10'))
        self.request_limit = int(os.getenv('GLOBAL_REQUEST_LIMIT', '100'))
        self.upload_limit = int(os.getenv('UPLOAD_REQUEST_LIMIT', '10'))
        
        # --- Behavioral Rules ---
        self.min_upload_delay = float(os.getenv('MIN_UPLOAD_DELAY', '1.5'))
        self.tracking_window = 60 
        
        # Internal state (Memory only - fail2ban handles persistence)
        self.access_log = {}         # {ip: [(timestamp, type_id), ...]}
        self.blocked_ips = {}         # {ip: expiry_timestamp} (Short-term process-local cache)
        self.first_seen = {}          # {(ip, client_id): timestamp}
        self.blocked_uas = set()      # Bot patterns
        
        self.ua_file = BLOCKED_UA_FILE
        self._load_uas()
        
        self.last_sync = time.time()
        self.last_prune = time.time()

    def _load_uas(self):
        """Load blocked UA patterns."""
        if os.path.exists(self.ua_file):
            try:
                with open(self.ua_file, 'r') as f:
                    self.blocked_uas = set(line.strip().lower() for line in f 
                                          if line.strip() and not line.startswith('#'))
            except:
                pass

    def get_ip(self):
        """Get the client's IP address securely."""
        remote_addr = request.remote_addr
        forwarded = request.environ.get('HTTP_X_FORWARDED_FOR')
        
        if forwarded and TRUSTED_PROXIES:
            try:
                client_addr = ipaddress.ip_address(remote_addr)
                if any(client_addr in net for net in TRUSTED_PROXIES):
                    return forwarded.split(',')[0].strip()
            except ValueError:
                pass
        return remote_addr

    def check_blocked(self):
        """Check if blocked. Skip in dev unless explicitly requested."""
        if self.is_dev:
            return

        ip = self.get_ip()
        now = time.time()
        
        # Sync UAs periodically
        if now - self.last_sync > 60:
            self._load_uas()
            self.last_sync = now

        # Check local memory cache (Process-local quick rejection)
        if ip in self.blocked_ips:
            if now < self.blocked_ips[ip]:
                abort(403, "Security protection: Access blocked.")
            else:
                del self.blocked_ips[ip]

        # User-Agent Check
        ua = request.get_header('User-Agent', '').lower()
        if ua and any(pattern in ua for pattern in self.blocked_uas):
            self._block_ip(ip, now, f"Blacklisted User-Agent: {ua}", original_action='CHECK_UA')

    def record_access(self, code=None, action=None, client_id=None):
        """Record and check access. Minimal in dev."""
        if self.is_dev:
            return

        ip = self.get_ip()
        if not ip: return
        
        now = time.time()
        if now - self.last_prune > 300: self._prune_logs(now)

        if ip not in self.access_log:
            self.access_log[ip] = []
            
        if client_id:
            key = (ip, client_id)
            if key not in self.first_seen:
                self.first_seen[key] = now

        self.access_log[ip].append((now, 'req'))
        if code: self.access_log[ip].append((now, f"code:{code}"))
        if action: self.access_log[ip].append((now, f"action:{action}"))
            
        ip_log = [e for e in self.access_log[ip] if now - e[0] <= 60]
        self.access_log[ip] = ip_log
        
        # --- DETECTION LOGIC ---
        
        # 1. Brute Force
        codes = len(set(e[1] for e in ip_log if e[1].startswith('code:')))
        if codes >= self.code_limit:
            self._block_ip(ip, now, "Brute Force Attempt", original_action=action or 'BRUTE_FORCE')

        # 2. Volumetric Attack
        req_count = len([e for e in ip_log if e[1] == 'req'])
        if not client_id:
            if req_count > 60: 
                self._block_ip(ip, now, "Anonymous Volumetric Attack", original_action=action or 'VOLUME')
            
            sessions = len([e for e in ip_log if e[1] == 'action:CREATE_SESSION'])
            if sessions > 5:
                self._block_ip(ip, now, "Bot Session Spike", original_action='CREATE_SESSION')
        else:
            if req_count > self.request_limit:
                self._block_ip(ip, now, "Aggressive Request Spike", original_action=action or 'SPIKE')

        # 3. Fast-Action Protection
        if action == 'UPLOAD':
            if client_id:
                start_time = self.first_seen.get((ip, client_id))
                if start_time and (now - start_time) < self.min_upload_delay:
                    self._block_ip(ip, now, "Bot Behavior (Instant Upload)", original_action='UPLOAD')
            
            uploads = len([e for e in ip_log if e[1] == 'action:UPLOAD'])
            if uploads > self.upload_limit:
                self._block_ip(ip, now, "Upload Flood Detected", original_action='UPLOAD')

    def _block_ip(self, ip, now, reason, original_action='SECURITY_VIOLATION'):
        """
        Detect a violation. 
        Log it as the ORIGINAL action with is_blocked flag for fail2ban.
        """
        print(f"SECURITY: Block Triggered for {ip}: {reason} during {original_action}")
        
        self.blocked_ips[ip] = now + 600 
        
        if self.logger_func:
            try:
                ua = request.get_header('User-Agent', 'Unknown')
                # Log using the attempted action name (e.g., CREATE_SESSION)
                # but with is_blocked=True so audit.py adds "status": "BLOCK_IP"
                self.logger_func(original_action, code=None, client_id=None, ip=ip, 
                               details={'reason': reason, 'ua': ua, 'is_blocked': True})
            except:
                pass

        abort(403, f"Security violation: {reason}. Access blocked.")

    def _prune_logs(self, now):
        """Cleanup memory state."""
        self.last_prune = now
        self.access_log = {ip: [e for e in l if now - e[0] <= 60] 
                          for ip, l in self.access_log.items()}
        self.access_log = {ip: l for ip, l in self.access_log.items() if l}
        self.first_seen = {k: v for k, v in self.first_seen.items() if now - v < 600}
        self.blocked_ips = {ip: exp for ip, exp in self.blocked_ips.items() if now < exp}

def security_plugin(protection):
    def plugin(callback):
        def wrapper(*args, **kwargs):
            if protection.is_dev: return callback(*args, **kwargs)
            
            client_id = None
            if request.json: client_id = request.json.get('clientId')
            if not client_id:
                client_id = request.forms.get('clientId') or request.query.get('clientId')
            
            action = 'UPLOAD' if (hasattr(callback, '__name__') and 'upload' in callback.__name__.lower()) else None
            protection.record_access(code=kwargs.get('code'), action=action, client_id=client_id)
            return callback(*args, **kwargs)
        return wrapper
    return plugin
