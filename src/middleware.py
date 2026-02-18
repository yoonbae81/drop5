import time
import os
import ipaddress
from bottle import request, abort
from src.config import TRUSTED_PROXIES

class SecurityMiddleware:
    def __init__(self, limit=None, window=None, block_duration=None):
        """
        Initialize security middleware for rate limiting and brute force protection.
        
        :param limit: Number of unique codes allowed within the window.
        :param window: Time window in seconds.
        :param block_duration: Duration to block the IP in seconds.
        """
        # Unique code limit (Brute force protection)
        self.code_limit = limit if limit is not None else int(os.getenv('BRUTE_FORCE_LIMIT', '10'))
        self.code_window = window if window is not None else int(os.getenv('BRUTE_FORCE_WINDOW', '60'))
        
        # Global request limit (DDoS protection)
        self.request_limit = int(os.getenv('GLOBAL_REQUEST_LIMIT', '50'))
        self.request_window = int(os.getenv('GLOBAL_REQUEST_WINDOW', '60'))
        
        # Expensive action limit (e.g. Uploads)
        self.upload_limit = int(os.getenv('UPLOAD_REQUEST_LIMIT', '10'))
        self.upload_window = int(os.getenv('UPLOAD_REQUEST_WINDOW', '60'))
        
        self.block_duration = block_duration if block_duration is not None else int(os.getenv('BRUTE_FORCE_BLOCK_DURATION', '3600'))
        
        # {ip: [(timestamp, type_id), ...]}
        # type_id: 'code:xyz', 'req', 'upload'
        self.access_log = {}
        # blocked_ips: {ip: expiry_timestamp}
        self.blocked_ips = {}

    def get_ip(self):
        """Get the client's IP address, handling potential reverse proxies securely."""
        remote_addr = request.remote_addr
        forwarded = request.environ.get('HTTP_X_FORWARDED_FOR')
        
        if forwarded and TRUSTED_PROXIES:
            try:
                client_addr = ipaddress.ip_address(remote_addr)
                # Only trust X-Forwarded-For if request came from a trusted proxy network
                if any(client_addr in net for net in TRUSTED_PROXIES):
                    # Handle list of IPs (client, proxy1, proxy2) - take the leftmost (client)
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
                remaining_min = remaining_sec // 60
                if remaining_min > 0:
                    msg = f"Security protection: Access denied. Try again in {remaining_min} minutes."
                else:
                    msg = f"Security protection: Access denied. Try again in {remaining_sec} seconds."
                abort(403, msg)
            else:
                # Block expired, remove it
                print(f"SECURITY: Block expired for IP {ip}")
                del self.blocked_ips[ip]

    def record_access(self, code=None, action=None):
        """Record an access attempt and check limits."""
        ip = self.get_ip()
        now = time.time()
        
        if ip not in self.access_log:
            self.access_log[ip] = []
            
        # 1. Record general request
        self.access_log[ip].append((now, 'req'))
        
        # 2. Record code access if provided
        if code:
            self.access_log[ip].append((now, f"code:{code}"))
            
        # 3. Record action if provided
        if action:
            self.access_log[ip].append((now, f"action:{action}"))
            
        # Cleanup old entries (use max window)
        max_window = max(self.code_window, self.request_window, self.upload_window)
        self.access_log[ip] = [entry for entry in self.access_log[ip] if now - entry[0] <= max_window]
        
        # Check Limits
        log = self.access_log[ip]
        
        # DDoS: Global request limit
        requests_in_window = [e for e in log if e[1] == 'req' and now - e[0] <= self.request_window]
        if len(requests_in_window) > self.request_limit:
            self._block_ip(ip, now, f"Rate limit exceeded ({len(requests_in_window)} requests/min).")
            
        # Brute Force: Unique codes limit
        codes_in_window = set(e[1] for e in log if e[1].startswith('code:') and now - e[0] <= self.code_window)
        if len(codes_in_window) >= self.code_limit:
            self._block_ip(ip, now, f"Brute force attempt detected ({len(codes_in_window)} codes/min).")
            
        # Expensive Actions: Upload limit
        if action == 'UPLOAD':
            uploads_in_window = [e for e in log if e[1] == 'action:UPLOAD' and now - e[0] <= self.upload_window]
            if len(uploads_in_window) > self.upload_limit:
                self._block_ip(ip, now, f"Upload frequency limit exceeded ({len(uploads_in_window)} uploads/min).")

    def _block_ip(self, ip, now, reason):
        """Block the IP and raise 403."""
        print(f"SECURITY: Blocking IP {ip} for reason: {reason}")
        self.blocked_ips[ip] = now + self.block_duration
        if ip in self.access_log:
            del self.access_log[ip]
        abort(403, f"Security violation: {reason} Access blocked.")

def security_plugin(protection):
    """
    Bottle plugin to wrap routes and record security events.
    """
    def plugin(callback):
        def wrapper(*args, **kwargs):
            # Extract action from route name or path if possible
            # But simpler: use kwargs['code'] for brute force
            code = kwargs.get('code')
            
            # Determine if this is an upload action
            action = None
            if hasattr(callback, '__name__') and 'upload' in callback.__name__.lower():
                action = 'UPLOAD'
            
            protection.record_access(code=code, action=action)
            return callback(*args, **kwargs)
        return wrapper
    return plugin
