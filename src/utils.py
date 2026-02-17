import os
import ipaddress
import re
import random
import unicodedata
import urllib.parse
from bottle import response, request
from src.config import UPLOAD_DIR, BLOCKED_FILE_EXTENSIONS, MAX_FILENAME_LENGTH, UMAMI_URL, TRUSTED_PROXIES

def get_client_ip():
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

def format_size(size_bytes):
    """Format bytes to kB or MB."""
    if size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} kB"
    return f"{size_bytes / (1024 * 1024):.1f} MB"

def decode_filename(filename):
    """Decode filename from various encoding formats used in multipart/form-data.
    
    Handles:
    - RFC2231: filename*=UTF-8''...
    - URL encoded filenames
    - Direct UTF-8 filenames
    """
    if not filename:
        return filename
    
    # Check for RFC2231 format: filename*=UTF-8''...
    if filename.startswith("UTF-8''"):
        # Extract the encoded part
        encoded = filename[7:]
        # URL decode it
        decoded = urllib.parse.unquote(encoded)
        return decoded
    
    # Try URL decoding
    try:
        decoded = urllib.parse.unquote(filename)
        # If decoding changed the string, use the decoded version
        if decoded != filename:
            return decoded
    except Exception:
        pass
    
    return filename

def sanitize_filename(filename):
    """Sanitize filename to prevent path traversal attacks.
    
    Removes directory components and validates the filename is safe.
    """
    if not filename:
        return None
    
    # First decode the filename from multipart encoding
    decoded = decode_filename(filename)
    
    # SECURITY: Reject filenames with null bytes
    if '\x00' in decoded:
        return None
    
    # Use os.path.basename to strip any directory components
    # This handles both Unix (/) and Windows (\) path separators
    safe_filename = os.path.basename(decoded)
    
    # Normalize path separators to handle mixed paths (e.g., ../..\)
    safe_filename = os.path.normpath(safe_filename)
    
    # After normpath, check if the filename contains path traversal indicators
    if '..' in safe_filename or safe_filename.startswith('/') or safe_filename.startswith('\\'):
        return None
    
    # SECURITY: Reject hidden files (starting with .) except .session.json
    if safe_filename.startswith('.') and safe_filename != '.session.json':
        return None
    
    # Reject empty filename after sanitization
    if not safe_filename or safe_filename in ('.', '..'):
        return None
    
    # SECURITY: Enforce maximum filename length
    if len(safe_filename) > MAX_FILENAME_LENGTH:
        return None
    
    return safe_filename

def normalize_filename(filename):
    """Normalize filename to NFC form for consistent display and UTF-8 encoding.
    
    Mac OS X often uses NFD (Normalization Form Decomposed) for filenames,
    while most other systems and web standards prefer NFC (Normalization Form Composed).
    This function ensures filenames are stored in NFC form to prevent "jaso separation"
    issues (e.g., Korean characters appearing decomposed).
    """
    # First sanitize the filename to prevent path traversal
    sanitized = sanitize_filename(filename)
    if not sanitized:
        return None
    # Normalize to NFC form (composed)
    normalized = unicodedata.normalize('NFC', sanitized)
    
    # SECURITY: Check file extension against blocked list
    _, ext = os.path.splitext(normalized.lower())
    if ext and ext in BLOCKED_FILE_EXTENSIONS:
        return None
    
    return normalized

def is_file_extension_blocked(filename):
    """Check if a file's extension is in the blocked list.
    
    Returns:
        tuple: (is_blocked: bool, extension: str or None)
    """
    if not filename:
        return False, None
    
    # First sanitize the filename
    sanitized = sanitize_filename(filename)
    if not sanitized:
        return False, None
    
    # Normalize to NFC form
    normalized = unicodedata.normalize('NFC', sanitized)
    
    # Check file extension against blocked list
    _, ext = os.path.splitext(normalized.lower())
    if ext and ext in BLOCKED_FILE_EXTENSIONS:
        return True, ext.lstrip('.')
    
    return False, None

def sanitize_session_code(code):
    """Sanitize and limit session code to prevent path traversal and resource abuse.
    
    SECURITY: Reject codes that contain path traversal indicators or are empty after sanitization.
    """
    if not code:
        return None
    # SECURITY: Check for path traversal indicators before sanitization
    code_str = str(code)
    if '..' in code_str or '/' in code_str or '\\' in code_str:
        return None
    # Allow only alphanumeric, hyphen, underscore.
    # Max length 128 characters (enough for long custom codes but safe for FS)
    sanitized = re.sub(r'[^a-zA-Z0-9\-_]', '', code_str)
    # SECURITY: Return None if sanitized result is empty or was significantly altered
    if not sanitized or len(sanitized) < 3:
        return None
    return sanitized[:128]

def generate_code():
    """Generate a unique 5-character alphanumeric code.
    
    SECURITY: Using alphanumeric characters (a-z, A-Z, 0-9) with case sensitivity
    for better security than numeric-only codes. 62^5 = ~916 million combinations.
    """
    # Characters: lowercase (26) + uppercase (26) + digits (10) = 62 total
    chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
    while True:
        code = ''.join(random.choices(chars, k=5))
        if not os.path.exists(os.path.join(UPLOAD_DIR, code)):
            return code

def validate_client_id(client_id):
    """Validate client ID format to prevent injection attacks.
    
    SECURITY: Client IDs should be UUID-like strings to prevent
    session fixation and impersonation attacks.
    """
    if not client_id:
        return False
    # Allow UUID format (hex chars with hyphens) or simple hex strings
    # Length should be reasonable (between 8 and 64 characters)
    if not isinstance(client_id, str):
        return False
    if len(client_id) < 8 or len(client_id) > 64:
        return False
    # Only allow alphanumeric, hyphen, and underscore
    if not re.match(r'^[a-zA-Z0-9\-_]+$', client_id):
        return False
    return True

def set_security_headers():
    """Set security HTTP headers to prevent various attacks.
    
    SECURITY: Headers protect against XSS, clickjacking, MIME sniffing, etc.
    """
    response.set_header('X-Content-Type-Options', 'nosniff')
    response.set_header('X-Frame-Options', 'DENY')
    response.set_header('X-XSS-Protection', '1; mode=block')
    response.set_header('Referrer-Policy', 'strict-origin-when-cross-origin')
    response.set_header('Permissions-Policy', 'geolocation=(), microphone=(), camera=()')
    # Content-Security-Policy for XSS protection
    csp = f"default-src 'self'; script-src 'self' 'unsafe-inline' {UMAMI_URL}; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self' data:; connect-src 'self' {UMAMI_URL} https://api-gateway.umami.dev;"
    response.set_header('Content-Security-Policy', csp)
