"""
Simplified Security Middleware for CrowdSec environment.

CrowdSec handles: Brute force, DoS/DDoS, IP blocking, User-Agent filtering
This middleware: Provides plugin interface and audit logging integration
"""

from bottle import request
from src.config import DEBUG


class SecurityMiddleware:
    def __init__(self, logger_func=None):
        """
        Initialize security middleware container.
        Security enforcement is delegated to CrowdSec.
        Audit logging is preserved for compliance.
        """
        self.logger_func = logger_func
        self.is_dev = DEBUG
        self.plugins = []

    def register_plugin(self, plugin):
        """Register a custom security plugin (extensibility)."""
        self.plugins.append(plugin)

    def check_blocked(self):
        """
        IP blocking is handled by CrowdSec bouncer.
        This method is kept for plugin compatibility only.
        """
        if self.is_dev:
            return

        # Plugin immediate checks (extensibility hook)
        if self.plugins:
            ip = self._get_client_ip()
            for plugin in self.plugins:
                should_block, reason, details = plugin.check_immediate(request, ip)
                if should_block:
                    self._log_security_block(ip, reason, details)
                    from bottle import abort
                    abort(403, f"Security violation: {reason}")

    def record_access(self, code=None, action=None, client_id=None):
        """
        Record access for audit logging (CrowdSec handles security enforcement).
        This preserves compliance logging: who uploaded/downloaded what files.
        """
        # Audit logging is handled directly in main.py via log_action()
        # This method is a no-op in CrowdSec environment but kept for compatibility
        pass

    def _get_client_ip(self):
        """Get client IP address."""
        from src.utils import get_client_ip
        return get_client_ip()

    def _log_security_block(self, ip, reason, details):
        """Log security block event for audit trail."""
        if self.logger_func:
            try:
                log_details = details or {}
                log_details.update({
                    'reason': reason,
                    'ua': request.get_header('User-Agent', 'Unknown'),
                    'is_blocked': True
                })
                self.logger_func('MALICIOUS_ACCESS', code=None, client_id=None, ip=ip, details=log_details)
            except Exception as e:
                print(f"Audit log error: {e}")


def security_plugin(protection):
    """Bottle plugin wrapper for security middleware."""
    def plugin(callback):
        def wrapper(*args, **kwargs):
            if protection.is_dev:
                return callback(*args, **kwargs)

            # Security checks (handled by CrowdSec)
            protection.check_blocked()

            # Audit logging is handled per-action in main.py
            return callback(*args, **kwargs)
        return wrapper
    return plugin
