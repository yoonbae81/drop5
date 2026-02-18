import time
import os
import ipaddress
import platform
from bottle import request, abort
import json
from src.config import TRUSTED_PROXIES, BLOCKED_UA_FILE, DEBUG

class SecurityMiddleware:
    def __init__(self, logger_func=None):
        """
        Initialize security middleware container.
        Actual security logic is delegated to registered plugins.
        """
        self.logger_func = logger_func
        self.is_dev = DEBUG
        self.plugins = []
        
        # Internal state for behavioral analysis
        # Shared across plugins to provide context
        self.access_log = {}         # {ip: [log_entry, ...]}
        self.blocked_ips = {}        # {ip: expiry_timestamp}
        self.last_prune = time.time()

    def register_plugin(self, plugin):
        """Register a security plugin."""
        self.plugins.append(plugin)

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
        """Check if blocked by IP (Local Cache)."""
        if self.is_dev: return

        ip = self.get_ip()
        now = time.time()
        
        # Check local memory cache
        if ip in self.blocked_ips:
            if now < self.blocked_ips[ip]:
                abort(403, "Security protection: Access blocked.")
            else:
                del self.blocked_ips[ip]

    def record_access(self, code=None, action=None, client_id=None):
        """
        Record access and run security plugins.
        """
        if self.is_dev: return

        ip = self.get_ip()
        if not ip: return
        
        now = time.time()
        
        # 1. Maintenance
        if now - self.last_prune > 300: self._prune_logs(now)
        
        # 2. Record Event
        if ip not in self.access_log:
            self.access_log[ip] = []
            
        event = {
            'timestamp': now,
            'action': action,
            'code': code,
            'client_id': client_id
        }
        self.access_log[ip].append(event)
        
        # Keep only recent history (last 60s) for analysis
        self.access_log[ip] = [e for e in self.access_log[ip] if now - e['timestamp'] <= 60]
        history = self.access_log[ip]

        # 3. Run Plugins
        for plugin in self.plugins:
            try:
                # Plugins return (actions_to_block, reason, details)
                should_block, reason, details = plugin.inspect(request, ip, history)
                if should_block:
                    self._block_ip(ip, now, reason, action, details)
                    break # Stop after first block
            except Exception as e:
                print(f"SECURITY: Plugin {plugin.name} error: {e}")

    def _block_ip(self, ip, now, reason, original_action, details=None):
        """
        Execute block and log verdict.
        """
        print(f"SECURITY: Block Triggered for {ip}: {reason} during {original_action}")
        
        # Local Block (10 min)
        self.blocked_ips[ip] = now + 600 
        
        # Log for fail2ban
        if self.logger_func:
            try:
                ua = request.get_header('User-Agent', 'Unknown')
                log_details = details or {}
                log_details.update({
                    'reason': reason, 
                    'ua': ua, 
                    'is_blocked': True # Trigger for verdict: BLOCK_IP
                })
                
                self.logger_func(original_action or 'MALICIOUS_ACCESS', 
                               code=None, client_id=None, ip=ip, 
                               details=log_details)
            except:
                pass

        abort(403, f"Security violation: {reason}. Access blocked.")

    def _prune_logs(self, now):
        """Cleanup memory state."""
        self.last_prune = now
        self.access_log = {ip: [e for e in l if now - e['timestamp'] <= 60] 
                          for ip, l in self.access_log.items()}
        self.access_log = {ip: l for ip, l in self.access_log.items() if l}
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
