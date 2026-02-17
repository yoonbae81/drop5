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
    Log structured JSON action record
    """
    log_entry = {
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime()), # Recorded in UTC
        'action': action,          # UPLOAD, DOWNLOAD, JOIN, DELETE
        'code': code,              # Session code
        'client_id': client_id,    # User ID
        'ip': ip,                  # IP Address
        'details': details or {}   # Filename, hash, etc.
    }
    # Record one line per JSON entry
    logger.info(json.dumps(log_entry, ensure_ascii=False))
