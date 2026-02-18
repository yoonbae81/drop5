import time
import os
import ipaddress
from bottle import request, abort
from src.config import TRUSTED_PROXIES

class SecurityMiddleware:
    def __init__(self, limit=None, window=None, block_duration=None):
        """
        Initialize security middleware for rate limiting and brute force protection.
        """
        # --- Per-IP Limits ---
        self.code_limit = limit if limit is not None else int(os.getenv('BRUTE_FORCE_LIMIT', '10'))
        self.code_window = window if window is not None else int(os.getenv('BRUTE_FORCE_WINDOW', '60'))
        
        self.request_limit = int(os.getenv('GLOBAL_REQUEST_LIMIT', '50'))
        self.request_window = int(os.getenv('GLOBAL_REQUEST_WINDOW', '60'))
        
        self.upload_limit = int(os.getenv('UPLOAD_REQUEST_LIMIT', '5')) # Tightened
        self.upload_window = int(os.getenv('UPLOAD_REQUEST_WINDOW', '60'))
        
        # --- System-Wide Limits (Global) ---
        self.system_request_limit = int(os.getenv('SYSTEM_REQUEST_LIMIT', '300')) # Tightened
        self.system_upload_limit = int(os.getenv('SYSTEM_UPLOAD_LIMIT', '50'))    # Tightened
        self.session_limit = int(os.getenv('SYSTEM_SESSION_LIMIT', '30'))          # Tightened
        self.hash_limit = int(os.getenv('DUPLICATE_HASH_LIMIT', '10'))
        self.system_window = int(os.getenv('SYSTEM_WINDOW', '60'))
        
        # --- Behavioral Rules ---
        self.min_upload_delay = float(os.getenv('MIN_UPLOAD_DELAY', '1.5')) # Seconds after appearance to allow UPLOAD
        
        self.block_duration = block_duration if block_duration is not None else int(os.getenv('BRUTE_FORCE_BLOCK_DURATION', '3600'))
        
        # Logs
        self.access_log = {}         # {ip: [(timestamp, type_id), ...]}
        self.system_access_log = []   # [(timestamp, type_id, ip, client_id), ...]
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
        
        # Security: Block common bot patterns (Empty User-Agent)
        ua = request.get_header('User-Agent', '')
        if not ua:
            # Most modern browsers provide UA. Simple bots often don't.
            # We don't block yet, but we could be stricter.
            pass

        if ip in self.blocked_ips:
            if now < self.blocked_ips[ip]:
                remaining_sec = int(self.blocked_ips[ip] - now)
                msg = f"Security protection: Access denied. Try again in {remaining_sec} seconds."
                abort(403, msg)
            else:
                print(f"SECURITY: Block expired for IP {ip}")
                del self.blocked_ips[ip]

    def record_access(self, code=None, action=None, client_id=None):
        """Record an access attempt and check both per-IP and system-wide limits."""
        ip = self.get_ip()
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

        # 1. Record Per-IP
        self.access_log[ip].append((now, 'req'))
        if code: self.access_log[ip].append((now, f"code:{code}"))
        if action: self.access_log[ip].append((now, f"action:{action}"))
        
        # 2. Record System-Wide
        self.system_access_log.append((now, 'req', ip, None))
        if action: self.system_access_log.append((now, f"action:{action}", ip, client_id))
            
        # Cleanup
        self.access_log[ip] = [e for e in self.access_log[ip] if now - e[0] <= self.system_window]
        self.system_access_log = [e for e in self.system_access_log if now - e[0] <= self.system_window]
        
        # --- PER-IP CHECKS ---
        ip_log = self.access_log[ip]
        if len([e for e in ip_log if e[1] == 'req']) > self.request_limit:
            self._block_ip(ip, now, "IP Rate Limit")
            
        codes = len(set(e[1] for e in ip_log if e[1].startswith('code:')))
        if codes >= self.code_limit:
            self._block_ip(ip, now, f"IP Brute Force ({codes} codes)")
            
        if action == 'UPLOAD':
            # BEHAVIOR CHECK: Too fast upload after appearance?
            if client_id:
                start_time = self.first_seen.get((ip, client_id))
                if start_time and (now - start_time) < self.min_upload_delay:
                    self._block_ip(ip, now, f"Behavior: Instant Upload ({now - start_time:.2f}s)")

            uploads = len([e for e in ip_log if e[1] == 'action:UPLOAD'])
            if uploads > self.upload_limit:
                self._block_ip(ip, now, f"IP Upload Frequency ({uploads}/min)")

        # --- SYSTEM-WIDE CHECKS ---
        # System Upload Limit
        sys_uploads = len([e for e in self.system_access_log if e[1] == 'action:UPLOAD'])
        if sys_uploads > self.system_upload_limit:
            print(f"SECURITY ALERT: System-wide upload spikes ({sys_uploads})")
            # If upload is high, we block ANY suspicious activity instantly
            if action == 'UPLOAD':
                self._block_ip(ip, now, "System Protection (High Load)")

        # System Session Creation Limit
        if action == 'CREATE_SESSION':
            sys_sessions = len([e for e in self.system_access_log if e[1] == 'action:CREATE_SESSION'])
            if sys_sessions > self.session_limit:
                 print(f"SECURITY: System session limit reached ({sys_sessions})")
                 abort(429, "Too Many New Sessions. Try again later.")

        # Duplicate Content Hash
        if action and action.startswith('hash:'):
            hash_val = action.split(':', 1)[1]
            duplicates = len([e for e in self.system_access_log if e[1] == f"action:hash:{hash_val}"])
            if duplicates > self.hash_limit:
                 self._block_ip(ip, now, "Duplicate Content Distribution (Spam/Malware)")

        # System Request Limit
        sys_reqs = len([e for e in self.system_access_log if e[1] == 'req'])
        if sys_reqs > self.system_request_limit:
             print(f"SECURITY: System-wide request limit exceeded ({sys_reqs})")
             abort(429, "Too Many Requests (System-wide)")

    def _block_ip(self, ip, now, reason):
        """Block the IP and raise 403."""
        print(f"SECURITY: Blocking IP {ip} for reason: {reason}")
        self.blocked_ips[ip] = now + self.block_duration
        if ip in self.access_log:
            del self.access_log[ip]
        abort(403, f"Security violation: {reason}. Access blocked.")

    def _prune_logs(self, now):
        """Prune all internal state to keep memory low."""
        self.last_prune = now
        # Prune access_log
        self.access_log = {ip: [e for e in l if now - e[0] <= self.system_window] 
                          for ip, l in self.access_log.items()}
        self.access_log = {ip: l for ip, l in self.access_log.items() if l}
            
        # Prune first_seen (keep for at least 5 mins)
        self.first_seen = {k: v for k, v in self.first_seen.items() if now - v < 300}
        
        # Prune blocked IPs
        self.blocked_ips = {ip: exp for ip, exp in self.blocked_ips.items() if now < exp}

def security_plugin(protection):
    """
    Bottle plugin to wrap routes and record security events.
    """
    def plugin(callback):
        def wrapper(*args, **kwargs):
            code = kwargs.get('code')
            
            # Try to find clientId in various request parts
            client_id = None
            if request.json:
                client_id = request.json.get('clientId')
            if not client_id:
                client_id = request.forms.get('clientId') or request.query.get('clientId')
            
            action = None
            if hasattr(callback, '__name__') and 'upload' in callback.__name__.lower():
                action = 'UPLOAD'
            
            # Explicitly record code/action
            protection.record_access(code=code, action=action, client_id=client_id)
            return callback(*args, **kwargs)
        return wrapper
    return plugin
