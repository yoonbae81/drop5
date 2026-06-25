import logging
import json
import hashlib
from logging.handlers import TimedRotatingFileHandler
import os
import time
import ipaddress
from src.config import AUDIT_DIR, MASK_IP_IN_LOGS

# Logger configuration
logger = logging.getLogger('audit_logger')
logger.setLevel(logging.INFO)

# Rotate log file every day at midnight (Retention: 90 days)
# Saved in audit/audit.log
handler = TimedRotatingFileHandler(
    os.path.join(AUDIT_DIR, 'audit.log'), 
    when='midnight', 
    interval=1, 
    backupCount=90,
    encoding='utf-8'
)
formatter = logging.Formatter('%(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

def mask_ip(ip_str, mask_octets=1):
    """Mask IP address for privacy protection (GDPR compliance).

    Args:
        ip_str: IP address string (IPv4 or IPv6)
        mask_octets: Number of octets/groups to mask (default: 1 for IPv4, 3 for IPv6)

    Returns:
        Masked IP string (e.g., "192.168.1.xxx" or "2001:db8::xxx")

    Examples:
        IPv4: mask_ip("192.168.1.100") -> "192.168.1.xxx"
        IPv4: mask_ip("192.168.1.100", 2) -> "192.168.xxx.xxx"
        IPv6: mask_ip("2001:db8::1") -> "2001:db8::xxx"
    """
    if not ip_str:
        return "unknown"

    try:
        ip = ipaddress.ip_address(ip_str)
        if ip.version == 4:
            # IPv4 masking: replace last N octets with 'xxx'
            octets = ip_str.split('.')
            masked_count = min(mask_octets, len(octets))
            for i in range(len(octets) - masked_count, len(octets)):
                octets[i] = 'xxx'
            return '.'.join(octets)
        else:
            # IPv6 masking: replace with simplified representation
            # For simplicity, mask the last groups
            groups = ip_str.split(':')
            # Handle :: compression
            if '::' in ip_str:
                # Expand :: for proper masking
                ip = ip.exploded
                groups = ip.split(':')

            masked_count = min(mask_octets if mask_octets > 2 else 3, len(groups))
            for i in range(len(groups) - masked_count, len(groups)):
                groups[i] = 'x'
            return ':'.join(groups)
    except (ValueError, ipaddress.AddressValueError):
        # Invalid IP, return masked placeholder
        return "invalid.xxx"


def calculate_file_hash(filepath):
    """Calculate SHA-256 hash of a file"""
    sha256 = hashlib.sha256()
    try:
        with open(filepath, 'rb') as f:
            while chunk := f.read(8192):
                sha256.update(chunk)
        return sha256.hexdigest()
    except IOError:
        return None

def log_action(action, code, client_id, ip, details=None):
    """
    Log structured JSON action record.
    Fields are ordered: timestamp, ip, action, etc. for fail2ban efficiency.

    Args:
        action: User action (CREATE_SESSION, UPLOAD, etc.)
        code: Session code
        client_id: User ID
        ip: Client IP address (will be masked based on MASK_IP_IN_LOGS config)
        details: Additional details (filename, reason, etc.)
    """
    # Create an ordered structure
    log_entry = {
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime()), # UTC
        'ip': mask_ip(ip) if MASK_IP_IN_LOGS else ip,  # IP Address (masked for privacy if enabled)
        'action': action,          # Original user action (CREATE_SESSION, UPLOAD, etc.)
        'code': code,              # Session code
        'client_id': client_id,    # User ID
        'details': details or {}   # Filename, reason, etc.
    }

    # If this is a security violation, add a verdict field that fail2ban can trigger on
    # Remove the internal flag 'is_blocked' from the details before logging
    if details and details.pop('is_blocked', False):
        log_entry['verdict'] = 'BLOCK_IP'

    logger.info(json.dumps(log_entry, ensure_ascii=False))
