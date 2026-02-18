import logging
import json
import hashlib
from logging.handlers import TimedRotatingFileHandler
import os
import time
from src.config import AUDIT_DIR

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
    """
    # Create an ordered structure
    log_entry = {
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime()), # UTC
        'ip': ip,                  # IP Address (Second field for easy parsing)
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
