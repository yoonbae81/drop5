import time
import os
import ipaddress
from bottle import request, abort
from src.config import TRUSTED_PROXIES

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
        self.access_log = {}         # {ip: [(timestamp, type_id), ...]}
        self.blocked_ips = {}         # {ip: expiry_timestamp}
        self.first_seen = {}          # {(ip, client_id): timestamp}
        
        # Pruning frequency
        self.last_prune = time.time()

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
        """Check if the current IP is blocked. Raise 403 if blocked."""
        ip = self.get_ip()
        now = time.time()
        
        if ip in self.blocked_ips:
            if now < self.blocked_ips[ip]:
                remaining_sec = int(self.blocked_ips[ip] - now)
                msg = f"Security protection: Access denied. Try again in {remaining_sec} seconds."
                abort(403, msg)
            else:
                print(f"SECURITY: Block expired for IP {ip}")
                del self.blocked_ips[ip]

    def record_access(self, code=None, action=None, client_id=None):
        """Record an access attempt and check per-IP behavioral limits."""
        ip = self.get_ip()
        if not ip: return
        
        now = time.time()
        
        if now - self.last_prune > 300:
            self._prune_logs(now)

        if ip not in self.access_log:
            self.access_log[ip] = []
            
        # TRACK BEHAVIOR: Record first time we see this client
        if client_id:
            key = (ip, client_id)
            if key not in self.first_seen:
                self.first_seen[key] = now

        # Record Per-IP Access
        self.access_log[ip].append((now, 'req'))
        if code: self.access_log[ip].append((now, f"code:{code}"))
        if action: self.access_log[ip].append((now, f"action:{action}"))
            
        # Cleanup IP log
        self.access_log[ip] = [e for e in self.access_log[ip] if now - e[0] <= self.tracking_window]
        ip_log = self.access_log[ip]
        
        # --- PER-IP SECURITY CHECKS ---
        
        # 1. Global Request Rate Limit
        if len([e for e in ip_log if e[1] == 'req']) > self.request_limit:
            self._block_ip(ip, now, "Rate Limit Exceeded")
            
        # 2. Brute Force (Unique Codes)
        codes = len(set(e[1] for e in ip_log if e[1].startswith('code:')))
        if codes >= self.code_limit:
            self._block_ip(ip, now, f"Brute Force Attempt ({codes} codes)")
            
        # 3. Behavioral: Instant Upload after JOIN
        if action == 'UPLOAD':
            if client_id:
                start_time = self.first_seen.get((ip, client_id))
                if start_time and (now - start_time) < self.min_upload_delay:
                    self._block_ip(ip, now, f"Bot Behavior Detected (Instant Upload)")

            uploads = len([e for e in ip_log if e[1] == 'action:UPLOAD'])
            if uploads > self.upload_limit:
                self._block_ip(ip, now, "Upload Frequency Exceeded")

        # 4. Behavioral: Multiple Session Creation
        if action == 'CREATE_SESSION':
            sessions = len([e for e in ip_log if e[1] == 'action:CREATE_SESSION'])
            if sessions > 5: # Max 5 new sessions/min per IP
                self._block_ip(ip, now, "Session Spamming Detected")

    def _block_ip(self, ip, now, reason):
        """Block the IP and raise 403."""
        print(f"SECURITY: Blocking IP {ip} for reason: {reason}")
        
        # Log the block action to audit log if logger is provided
        if self.logger_func:
            try:
                self.logger_func('BLOCK_IP', code=None, client_id=None, ip=ip, details={'reason': reason})
            except:
                pass

        self.blocked_ips[ip] = now + self.block_duration
        if ip in self.access_log:
            del self.access_log[ip]
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
