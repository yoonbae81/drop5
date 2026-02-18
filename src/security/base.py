from datetime import datetime

class BaseSecurityPlugin:
    """Base class for all security plugins."""
    
    def __init__(self, name):
        self.name = name

    def inspect(self, request, ip, access_log):
        """
        Inspect a request and decide whether to block it.
        
        :param request: The Bottle request object
        :param ip: Client IP address
        :param access_log: List of recent access logs for behavioral analysis
        :return: (is_blocked, reason, details)
           - is_blocked: Boolean
           - reason: String for simple logging
           - details: Dict for detailed audit log
        """
        raise NotImplementedError("Plugins must implement inspect()")

    def on_block(self, ip, reason):
        """Optional hook when a block occurs."""
        pass
