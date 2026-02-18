import os
import ipaddress
from bottle import BaseRequest, TEMPLATE_PATH

# Increase maximum body size to 100MB (default is 100KB)
BaseRequest.MEMFILE_MAX = 100 * 1024 * 1024

# Configuration
UPLOAD_DIR = os.path.abspath(os.getenv('UPLOAD_DIR', 'files'))
FILE_TIMEOUT = int(os.getenv('FILE_TIMEOUT', 300))  # seconds
MAX_FILE_SIZE = int(os.getenv('MAX_FILE_SIZE', 31457280))  # bytes (30MB)
MAX_STORAGE_SIZE = int(os.getenv('MAX_STORAGE_SIZE', 104857600))  # bytes (100MB per folder)
AUDIT_DIR = os.path.abspath(os.getenv('AUDIT_DIR', 'audit'))
SECURITY_DIR = os.path.abspath(os.getenv('SECURITY_DIR', 'security'))
BLOCKED_UA_FILE = os.path.join(SECURITY_DIR, 'blocked_uas.txt')
BLOCKED_IP_FILE = os.path.join(SECURITY_DIR, 'blocked_ips.json')
TRUSTED_IP_TIMEOUT = 86400  # 24 hours in seconds
PORT = int(os.getenv('PORT', 5555))
# SECURITY: Default to false in production to prevent information disclosure
DEBUG = os.getenv('DEBUG', 'false').lower() == 'true'

# REGION-BASED RESTRICTIONS
# List of country codes (ISO alpha-2) to operate in restricted mode
# Common sources of abuse: RU (Russia), UA (Ukraine), BY (Belarus), VN (Vietnam), CN (China), ID (Indonesia), PK (Pakistan)
RESTRICTED_COUNTRIES = set(
    c.strip().upper() 
    for c in os.getenv('RESTRICTED_COUNTRIES', '').split(',') 
    if c.strip()
)
MAX_FILES_NORMAL = int(os.getenv('MAX_FILES_NORMAL', '30'))
MAX_FILES_RESTRICTED = int(os.getenv('MAX_FILES_RESTRICTED', '5'))

# SECURITY: Trusted proxies for IP detection (comma-separated list of IPs or CIDR networks)
# Only trust X-Forwarded-For if it comes from these networks.
# If empty, it's assumed the server is not behind a proxy or you trust the gateway.
TRUSTED_PROXIES = []
for p in os.getenv('TRUSTED_PROXIES', '').split(','):
    p = p.strip()
    if p:
        try:
            # strict=False allows host bits to be set (e.g., 10.0.0.1/24)
            TRUSTED_PROXIES.append(ipaddress.ip_network(p, strict=False))
        except ValueError:
            pass

# SECURITY: Blocked file extensions to prevent malicious file uploads
# Read from BLOCKED_FILE_EXTENSIONS environment variable (comma-separated, without leading dot)
# Default: Block executable files and potentially dangerous file types
DEFAULT_BLOCKED_EXTENSIONS = [
    'exe', 'bat', 'cmd', 'com', 'pif', 'scr', 'vbs', 'msi', 'jar', 'app'
]
BLOCKED_FILE_EXTENSIONS = set(
    f'.{ext.strip().lower()}'
    for ext in os.getenv('BLOCKED_FILE_EXTENSIONS', ','.join(DEFAULT_BLOCKED_EXTENSIONS)).split(',')
    if ext.strip()
)

# Maximum filename length to prevent filesystem issues
MAX_FILENAME_LENGTH = 255

BASE_URL = os.getenv('BASE_URL', '/drop5').strip()
if not BASE_URL:
    BASE_URL = '/'

# Check if BASE_URL is a full URL (http:// or https://)
is_full_url = BASE_URL.startswith('http://') or BASE_URL.startswith('https://')

if not is_full_url:
    # For path prefixes, ensure it starts with /
    if not BASE_URL.startswith('/'):
        BASE_URL = '/' + BASE_URL
    # Ensure BASE_URL doesn't end with / for consistent joins, unless it's just "/"
    if len(BASE_URL) > 1:
        BASE_URL = BASE_URL.rstrip('/')

# URL_PREFIX is used for constructing routes like f'{URL_PREFIX}/<code>'
# If BASE_URL is a full URL or "/", URL_PREFIX should be empty
URL_PREFIX = '' if is_full_url or BASE_URL == '/' else BASE_URL

# Template configuration
TEMPLATE_PATH.insert(0, os.path.join(os.path.dirname(__file__), 'views'))

# i18n Configuration
DEFAULT_LANGUAGE = 'en'  # Base language
LANGUAGE_COOKIE_NAME = 'drop5_lang'

# Umami Analytics Configuration
UMAMI_ID = os.getenv('UMAMI_ID', '')
UMAMI_URL = os.getenv('UMAMI_URL', 'https://cloud.umami.is')

# Branding & Contact Information
CONTACT_EMAIL = os.getenv('CONTACT_EMAIL', '')
COMPANY_NAME = os.getenv('COMPANY_NAME', '')

# Ensure directories exist
if not os.path.exists(UPLOAD_DIR):
    os.makedirs(UPLOAD_DIR, exist_ok=True)
if not os.path.exists(AUDIT_DIR):
    os.makedirs(AUDIT_DIR, exist_ok=True)
if not os.path.exists(SECURITY_DIR):
    os.makedirs(SECURITY_DIR, exist_ok=True)