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
        
        self.upload_limit = int(os.getenv('UPLOAD_REQUEST_LIMIT', '10'))
        self.upload_window = int(os.getenv('UPLOAD_REQUEST_WINDOW', '60'))
        
        # --- System-Wide Limits (Global) ---
        self.system_request_limit = int(os.getenv('SYSTEM_REQUEST_LIMIT', '500'))
        self.system_upload_limit = int(os.getenv('SYSTEM_UPLOAD_LIMIT', '100'))
        self.session_limit = int(os.getenv('SYSTEM_SESSION_LIMIT', '50')) # Max new sessions system-wide/min
        self.hash_limit = int(os.getenv('DUPLICATE_HASH_LIMIT', '15')) # Max times SAME hash can be uploaded system-wide/min
        self.system_window = int(os.getenv('SYSTEM_WINDOW', '60'))
        
        self.block_duration = block_duration if block_duration is not None else int(os.getenv('BRUTE_FORCE_BLOCK_DURATION', '3600'))
        
        # Logs
        self.access_log = {}         # {ip: [(timestamp, type_id), ...]}
        self.system_access_log = []   # [(timestamp, type_id, ip), ...]
        self.blocked_ips = {}         # {ip: expiry_timestamp}
        
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

    def record_access(self, code=None, action=None):
        """Record an access attempt and check both per-IP and system-wide limits."""
        ip = self.get_ip()
        now = time.time()
        
        # Periodically prune old logs to save memory
        if now - self.last_prune > 300: # Every 5 minutes
            self._prune_logs(now)

        if ip not in self.access_log:
            self.access_log[ip] = []
            
        # 1. Record Per-IP
        self.access_log[ip].append((now, 'req'))
        if code: self.access_log[ip].append((now, f"code:{code}"))
        if action: self.access_log[ip].append((now, f"action:{action}"))
        
        # 2. Record System-Wide
        self.system_access_log.append((now, 'req', ip))
        if action: self.system_access_log.append((now, f"action:{action}", ip))
            
        # Cleanup IP log
        self.access_log[ip] = [e for e in self.access_log[ip] if now - e[0] <= self.system_window]
        
        # Check Per-IP Limits
        ip_log = self.access_log[ip]
        
        # IP Rate Limit
        if len([e for e in ip_log if e[1] == 'req']) > self.request_limit:
            self._block_ip(ip, now, "IP Rate Limit")
            
        # IP Brute Force
        codes = len(set(e[1] for e in ip_log if e[1].startswith('code:')))
        if codes >= self.code_limit:
            self._block_ip(ip, now, f"IP Brute Force ({codes} codes)")
            
        # IP Action Limit
        if action == 'UPLOAD':
            uploads = len([e for e in ip_log if e[1] == 'action:UPLOAD'])
            if uploads > self.upload_limit:
                self._block_ip(ip, now, f"IP Upload Frequency ({uploads}/min)")

        # Check System-Wide Limits (Distributed Attack Protection)
        # Cleanup system log
        self.system_access_log = [e for e in self.system_access_log if now - e[0] <= self.system_window]
        
        # System Session Creation Limit
        if action == 'CREATE_SESSION':
            sys_sessions = len([e for e in self.system_access_log if e[1] == 'action:CREATE_SESSION'])
            if sys_sessions > self.session_limit:
                 print(f"SECURITY: System-wide session limit reached ({sys_sessions})")
                 # We don't necessarily block the IP for just creating sessions, but we stop the request
                 abort(429, "Too Many New Sessions. Please wait a minute.")

        # System Upload Limit
        sys_uploads = len([e for e in self.system_access_log if e[1] == 'action:UPLOAD'])
        if sys_uploads > self.system_upload_limit:
            print(f"SECURITY: System-wide upload limit exceeded ({sys_uploads})")
            self._block_ip(ip, now, "System-wide Upload Limit reached (Distributed Attack Detected)")

        # System Duplicate Hash Limit (Malware/Spam Distribution)
        if action and action.startswith('hash:'):
            hash_val = action.split(':', 1)[1]
            duplicates = len([e for e in self.system_access_log if e[1] == f"action:hash:{hash_val}"])
            if duplicates > self.hash_limit:
                 print(f"SECURITY: System-wide duplicate hash limit reached for {hash_val[:10]}... ({duplicates})")
                 self._block_ip(ip, now, "System-wide Duplicate Content Limit (Spam/Malware Detection)")

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
        """Prune all logs older than the tracking window."""
        self.last_prune = now
        # Prune access_log keys
        dead_ips = []
        for ip, log in self.access_log.items():
            new_log = [e for e in log if now - e[0] <= self.system_window]
            if not new_log:
                dead_ips.append(ip)
            else:
                self.access_log[ip] = new_log
        for ip in dead_ips:
            del self.access_log[ip]
            
        # Prune blocked IPs
        expired = [ip for ip, expiry in self.blocked_ips.items() if now > expiry]
        for ip in expired:
            del self.blocked_ips[ip]

def security_plugin(protection):
    """
    Bottle plugin to wrap routes and record security events.
    """
    def plugin(callback):
        def wrapper(*args, **kwargs):
            code = kwargs.get('code')
            action = None
            if hasattr(callback, '__name__') and 'upload' in callback.__name__.lower():
                action = 'UPLOAD'
            
            protection.record_access(code=code, action=action)
            return callback(*args, **kwargs)
        return wrapper
    return plugin
