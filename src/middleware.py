import time
import os
import ipaddress
from bottle import request, abort
from src.config import TRUSTED_PROXIES

class BruteForceProtection:
    def __init__(self, limit=None, window=None, block_duration=None):
        """
        Initialize brute force protection.
        
        SECURITY: Reads configuration from environment variables if not provided.
        
        :param limit: Number of unique codes allowed within the window.
        :param window: Time window in seconds.
        :param block_duration: Duration to block the IP in seconds.
        """
        # SECURITY: Read from environment variables for production configuration
        self.limit = limit if limit is not None else int(os.getenv('BRUTE_FORCE_LIMIT', '10'))
        self.window = window if window is not None else int(os.getenv('BRUTE_FORCE_WINDOW', '60'))
        self.block_duration = block_duration if block_duration is not None else int(os.getenv('BRUTE_FORCE_BLOCK_DURATION', '3600'))
        
        # access_log: {ip: [(timestamp, code), ...]}
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
        
        # If no trusted proxies defined, but we are behind one, this might need fallback 
        # but for security, if TRUSTED_PROXIES is defined, we enforce it.
        # If TRUSTED_PROXIES is empty, we don't trust XFF at all to prevent spoofing.
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
                    msg = f"Brute force protection: Access denied. Try again in {remaining_min} minutes."
                else:
                    msg = f"Brute force protection: Access denied. Try again in {remaining_sec} seconds."
                abort(403, msg)
            else:
                # Block expired, remove it
                del self.blocked_ips[ip]

    def record_access(self, code):
        """Record an access attempt to a specific code."""
        if not code:
            return
            
        ip = self.get_ip()
        now = time.time()
        
        # Initialize log for this IP if not present
        if ip not in self.access_log:
            self.access_log[ip] = []
            
        # Add current access
        self.access_log[ip].append((now, str(code)))
        
        # Cleanup old entries outside the window
        self.access_log[ip] = [entry for entry in self.access_log[ip] if now - entry[0] <= self.window]
        
        # Count unique codes accessed in the window
        unique_codes = set(entry[1] for entry in self.access_log[ip])
        
        if len(unique_codes) >= self.limit:
            # Block the IP
            self.blocked_ips[ip] = now + self.block_duration
            # Clear their access log
            if ip in self.access_log:
                del self.access_log[ip]
            
            abort(403, "Brute force attempt detected. Access blocked for 1 hour.")

def brute_force_plugin(protection):
    """
    Bottle plugin to wrap routes and record code access.
    """
    def plugin(callback):
        def wrapper(*args, **kwargs):
            # Check for 'code' in route parameters
            if 'code' in kwargs:
                protection.record_access(kwargs['code'])
            return callback(*args, **kwargs)
        return wrapper
    return plugin
