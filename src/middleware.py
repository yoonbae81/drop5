import time
import os
import ipaddress
from bottle import request, abort, json
from src.config import TRUSTED_PROXIES, BLOCKED_UA_FILE, BLOCKED_IP_FILE

class SecurityMiddleware:
    def __init__(self, limit=None, window=None, block_duration=None, logger_func=None):
        """
        Initialize security middleware for per-IP rate limiting and behavioral protection.
        """
        self.logger_func = logger_func
        # --- Per-IP Limits ---
        self.code_limit = limit if limit is not None else int(os.getenv('BRUTE_FORCE_LIMIT', '10'))
        self.code_window = window if window is not None else int(os.getenv('BRUTE_FORCE_WINDOW', '60'))
        
        self.request_limit = int(os.getenv('GLOBAL_REQUEST_LIMIT', '100'))
        self.request_window = int(os.getenv('GLOBAL_REQUEST_WINDOW', '60'))
        
        self.upload_limit = int(os.getenv('UPLOAD_REQUEST_LIMIT', '10'))
        self.upload_window = int(os.getenv('UPLOAD_REQUEST_WINDOW', '60'))
        
        # --- Behavioral Rules ---
        self.min_upload_delay = float(os.getenv('MIN_UPLOAD_DELAY', '1.5'))
        self.tracking_window = 60 # Default window for IP tracking
        
        self.block_duration = block_duration if block_duration is not None else int(os.getenv('BRUTE_FORCE_BLOCK_DURATION', '3600'))
        
        # Logs
        # Shared Block Files
        self.block_file = BLOCKED_IP_FILE
        self.ua_file = BLOCKED_UA_FILE
        
        # Logs
        self.access_log = {}         # {ip: [(timestamp, type_id), ...]}
        self.blocked_ips = {}         # {ip: expiry_timestamp}
        self.first_seen = {}          # {(ip, client_id): timestamp}
        self.blocked_uas = set()      # Dynamic set from file
        
        # Initial load and sync
        self._load_blocks()
        self._load_uas()
        
        # Tracking for refresh
        self.last_sync = time.time()
        self.last_prune = time.time()

    def _load_blocks(self):
        """Load blocked IPs from shared file for multi-process sync."""
        if os.path.exists(self.block_file):
            try:
                with open(self.block_file, 'r') as f:
                    data = json.load(f)
                    now = time.time()
                    self.blocked_ips.update({ip: exp for ip, exp in data.items() if exp > now})
            except:
                pass

    def _save_block(self, ip, expiry):
        """Save block to shared file."""
        self._load_blocks() # Refresh
        self.blocked_ips[ip] = expiry
        try:
            with open(self.block_file, 'w') as f:
                json.dump(self.blocked_ips, f)
        except:
            pass

    def _load_uas(self):
        """Load blocked UA patterns from the security file."""
        if os.path.exists(self.ua_file):
            try:
                with open(self.ua_file, 'r') as f:
                    self.blocked_uas = set(line.strip().lower() for line in f 
                                          if line.strip() and not line.startswith('#'))
            except:
                pass

    def get_ip(self):
        """Get the client's IP address, handling potential reverse proxies securely."""
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
        """Check if the current IP or User-Agent is blocked. Raise 403 if blocked."""
        ip = self.get_ip()
        now = time.time()
        ua = request.get_header('User-Agent', '').lower()
        
        # Periodically refresh from shared blocks
        if now - self.last_sync > 60:
            self._load_blocks()
            self._load_uas()
            self.last_sync = now

        # 1. Check User-Agent Blacklist (Instant)
        if ua:
            if any(pattern in ua for pattern in self.blocked_uas):
                # Log the blocked UA attempt
                if self.logger_func:
                    try:
                         self.logger_func('BLOCK_UA', code=None, client_id=None, ip=ip, details={'ua': ua, 'reason': 'UA Blacklist'})
                    except: pass
                abort(403, "Access denied: Malicious tool detected.")

        # 2. Check IP Blocklist
        if ip in self.blocked_ips:
            if now < self.blocked_ips[ip]:
                abort(403, "Security protection: Access blocked.")
            else:
                del self.blocked_ips[ip]

    def record_access(self, code=None, action=None, client_id=None):
        """Record and check access using a behavioral-centric model."""
        ip = self.get_ip()
        if not ip: return
        
        now = time.time()
        if now - self.last_prune > 300: self._prune_logs(now)

        if ip not in self.access_log:
            self.access_log[ip] = []
            
        # 1. Behavioral Tracking
        if client_id:
            key = (ip, client_id)
            if key not in self.first_seen:
                self.first_seen[key] = now

        self.access_log[ip].append((now, 'req'))
        if code: self.access_log[ip].append((now, f"code:{code}"))
        if action: self.access_log[ip].append((now, f"action:{action}"))
            
        # Cleanup IP log window (Default 60s)
        self.access_log[ip] = [e for e in self.access_log[ip] if now - e[0] <= 60]
        ip_log = self.access_log[ip]
        
        # --- SIMPLE BEHAVIORAL CHECKS ---
        
        # 1. Brute Force (Unique codes) - Keep this as it's targeted
        codes = len(set(e[1] for e in ip_log if e[1].startswith('code:')))
        if codes >= self.code_limit:
            self._block_ip(ip, now, f"Brute Force Attempt")

        # 2. Advanced Bot Detection (No ClientID + High Frequency)
        req_count = len([e for e in ip_log if e[1] == 'req'])
        if not client_id:
            # Absolute limit for mysterious anonymous requests
            if req_count > 20: 
                self._block_ip(ip, now, "Anonymous Volumetric Attack")
            
            # Anonymous session spamming is high risk
            sessions = len([e for e in ip_log if e[1] == 'action:CREATE_SESSION'])
            if sessions > 1:
                self._block_ip(ip, now, "Bot Session Spike")
        else:
            # Regular user limit (Higher, but still protective)
            if req_count > self.request_limit:
                self._block_ip(ip, now, "Aggressive Request Spike")

        # 3. Fast-Action Protection (Instant Upload)
        if action == 'UPLOAD':
            if client_id:
                start_time = self.first_seen.get((ip, client_id))
                if start_time and (now - start_time) < self.min_upload_delay:
                    self._block_ip(ip, now, "Bot Behavior (Instant Upload)")
            
            # Upload frequency check
            uploads = len([e for e in ip_log if e[1] == 'action:UPLOAD'])
            if uploads > self.upload_limit:
                self._block_ip(ip, now, "Upload Flood Detected")

    def _block_ip(self, ip, now, reason):
        """Block the IP and raise 403."""
        print(f"SECURITY: Blocking IP {ip} for reason: {reason}")
        expiry = now + self.block_duration
        
        # Persistence across workers
        self._save_block(ip, expiry)
        
        # Log the block action
        if self.logger_func:
            try:
                ua = request.get_header('User-Agent', 'Unknown')
                self.logger_func('BLOCK_IP', code=None, client_id=None, ip=ip, details={'reason': reason, 'ua': ua})
            except:
                pass

        abort(403, f"Security violation: {reason}. Access blocked.")

    def _prune_logs(self, now):
        """Prune all internal state to keep memory low."""
        self.last_prune = now
        self.access_log = {ip: [e for e in l if now - e[0] <= self.tracking_window] 
                          for ip, l in self.access_log.items()}
        self.access_log = {ip: l for ip, l in self.access_log.items() if l}
        self.first_seen = {k: v for k, v in self.first_seen.items() if now - v < 600}
        self.blocked_ips = {ip: exp for ip, exp in self.blocked_ips.items() if now < exp}

def security_plugin(protection):
    """
    Bottle plugin to wrap routes and record security events.
    """
    def plugin(callback):
        def wrapper(*args, **kwargs):
            code = kwargs.get('code')
            
            # Extract clientId
            client_id = None
            if request.json:
                client_id = request.json.get('clientId')
            if not client_id:
                client_id = request.forms.get('clientId') or request.query.get('clientId')
            
            action = None
            if hasattr(callback, '__name__') and 'upload' in callback.__name__.lower():
                action = 'UPLOAD'
            
            protection.record_access(code=code, action=action, client_id=client_id)
            return callback(*args, **kwargs)
        return wrapper
    return plugin
