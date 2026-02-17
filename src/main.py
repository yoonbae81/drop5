#!/usr/bin/env python3

from bottle import Bottle, request, response, static_file, redirect, abort, template
import os
import time
import re
import json
import traceback
try:
    from script_reporter import ScriptReporter
except ImportError:
    ScriptReporter = None

from src.config import (
    UPLOAD_DIR, FILE_TIMEOUT, MAX_FILE_SIZE, MAX_STORAGE_SIZE,
    PORT, DEBUG, BASE_URL, URL_PREFIX, DEFAULT_LANGUAGE, LANGUAGE_COOKIE_NAME,
    UMAMI_ID, UMAMI_URL, RESTRICTED_COUNTRIES, MAX_FILES_NORMAL, MAX_FILES_RESTRICTED,
    CONTACT_EMAIL, COMPANY_NAME
)
from src.utils import (
    format_size, sanitize_filename, normalize_filename,
    sanitize_session_code, generate_code, validate_client_id,
    set_security_headers, get_client_ip, is_file_extension_blocked
)
from src.session import (
    get_session_size, cleanup_session, cleanup_all_sessions,
    get_active_files, load_session_state, save_session_state,
    cleanup_stale_clients, is_client_approved, clear_session_files,
    update_session_state
)
from src.audit import log_action, calculate_file_hash
from src.i18n import detect_language, get_translations, get_available_languages, get_native_language_info, SUPPORTED_LANGUAGES, search_country

app = Bottle()

# Initialize Error Reporter
reporter = None
if ScriptReporter:
    reporter = ScriptReporter("Drop5")
    
    # Global exception hook for fatal errors outside request context
    import sys
    def global_excepthook(exctype, value, tb):
        reporter.fail(f"Fatal Service Error: {exctype.__name__}: {value}\n\n"
                      f"{''.join(traceback.format_exception(exctype, value, tb))}")
        sys.__excepthook__(exctype, value, tb)
    sys.excepthook = global_excepthook

    # Report successful startup
    reporter.success({"status": "Service Started", "port": PORT, "debug": DEBUG})


class DictWrapper:
    """Wrapper class to allow attribute access to dictionary keys for Bottle templates."""
    def __init__(self, data):
        self._data = data
    
    def __getattr__(self, name):
        if name in self._data:
            return self._data[name]
        raise AttributeError(f"'{type(self).__name__}' object has no attribute '{name}'")

# Brute force protection: Reads from environment variables or uses defaults
try:
    from middleware import BruteForceProtection, brute_force_plugin
except ImportError:
    from src.middleware import BruteForceProtection, brute_force_plugin

# SECURITY: Use environment variables for configurable brute force protection
protection = BruteForceProtection(
    limit=int(os.getenv('BRUTE_FORCE_LIMIT', '10')),
    window=int(os.getenv('BRUTE_FORCE_WINDOW', '60')),
    block_duration=int(os.getenv('BRUTE_FORCE_BLOCK_DURATION', '3600'))
)
app.install(brute_force_plugin(protection))

@app.hook('before_request')
def check_brute_force():
    protection.check_blocked()

@app.error(500)
def error500(error):
    """Handle unhandled exceptions and report them if reporter is active."""
    if reporter:
        # Extract exception and traceback if available
        err_msg = "Unknown Internal Error"
        tb = "No traceback available"
        
        if hasattr(error, 'exception') and error.exception:
            err_msg = str(error.exception)
            # Try to get traceback from exception or current context
            tb = getattr(error, 'traceback', None) or traceback.format_exc()
        
        reporter.fail(f"Unhandled Exception: {err_msg}\n\n{tb}")
    
    # Return a generic error page (or let Bottle handle the response body)
    return template('<b>Internal Server Error</b><p>Something went wrong. The error has been reported.</p>')

def auto_approve_if_solo(client_id, state):
    """
    In-place update for state: auto-approves client if session has no host.
    Returns True if approved (already or newly), False otherwise.
    """
    if not client_id or not validate_client_id(client_id):
        return False
        
    if is_client_approved(state, client_id):
        # Update heartbeat
        if client_id in state['clients']:
            state['clients'][client_id]['last_seen'] = time.time()
        return True
    
    # Accurate has_host check
    cleanup_stale_clients(state)
    has_host = any(c['status'] == 'approved' for c in state['clients'].values())
    
    ip = get_client_ip()
    trusted_ips = state.get('trusted_ips', {})
    is_trusted = isinstance(trusted_ips, dict) and ip in trusted_ips

    if not has_host or is_trusted:
        state['clients'][client_id] = {
            'status': 'approved',
            'last_seen': time.time(),
            'joined_at': state['clients'].get(client_id, {}).get('joined_at', time.time()),
            'ip': ip,
            'browser': request.get_header('User-Agent')
        }
        # Mark IP as trusted
        if not isinstance(state.get('trusted_ips'), dict):
            state['trusted_ips'] = {}
        state['trusted_ips'][ip] = time.time()
        return True
    
    return False

def check_approval_or_auto_approve(code, client_id, code_dir):
    """Check if client is approved, or auto-approve if no host exists in the session.
    
    Wrapper around auto_approve_if_solo using update_session_state for atomicity.
    """
    approval_res = [False]
    def callback(state):
        approval_res[0] = auto_approve_if_solo(client_id, state)
    update_session_state(code_dir, callback)
    return approval_res[0]


@app.route(f'{URL_PREFIX}/<code>/files')
@app.route('/<code>/files')
def files_api(code):
    """API for real-time file list updates."""
    set_security_headers()
    
    code = sanitize_session_code(code)
    if not code or code in ('style.css', 'app.js', 'stylecss', 'appjs'):
        return {'success': False, 'error': 'Invalid code'}
    
    client_id = request.query.get('clientId')
    # SECURITY: Validate client ID format
    if not validate_client_id(client_id):
        return {'success': False, 'error': 'Invalid client ID'}
    
    code_dir = os.path.join(UPLOAD_DIR, code)
    
    # Security check
    if not check_approval_or_auto_approve(code, client_id, code_dir):
        return {'success': False, 'error': 'Unauthorized', 'status': 'pending'}

    cleanup_session(code_dir)
    files = get_active_files(code_dir)
    
    response.set_header('Content-Type', 'application/json')
    response.set_header('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0')
    return {'success': True, 'files': files}

@app.route('/')
@app.route(f"{URL_PREFIX}" if URL_PREFIX else None)
@app.route(f"{URL_PREFIX}/" if URL_PREFIX else None)
def home():
    """Generate session and redirect."""
    set_security_headers()
    
    cleanup_all_sessions()
    code = generate_code()
    # Ensure directory exists before redirecting
    os.makedirs(os.path.join(UPLOAD_DIR, code), exist_ok=True)
    
    # Construct redirect URL carefully using the calculated prefix
    target = f"{URL_PREFIX}/{code}" if URL_PREFIX else f"/{code}"
    redirect(target)

# Static file routes - must be defined before /<code> route to prevent them from being treated as session codes
@app.route(f'{URL_PREFIX}/style.css')
@app.route('/style.css')
def serve_style_css():
    """Serve the static CSS file."""
    set_security_headers()
    views_dir = os.path.join(os.path.dirname(__file__), 'views')
    return static_file('style.css', root=views_dir)

@app.route(f'{URL_PREFIX}/app.js')
@app.route('/app.js')
def serve_app_js():
    """Serve the JS file as a template with session-specific variables."""
    set_security_headers()
    
    # 1. Try to get code from query parameter (most reliable if passed)
    code = sanitize_session_code(request.query.get('code'))
    
    # 2. If not in query, try to get code from Referer header
    if not code:
        referer = request.headers.get('Referer', '')
        if referer:
            # Extract code from URL like http://localhost:8080/abc123 or http://localhost:8080/drop5/abc123
            match = re.search(r'/([^/]+)(?:/)?$', referer)
            if match:
                potential_code = match.group(1)
                # Filter out static files and common paths
                if potential_code not in ('static', 'style.css', 'app.js', 'stylecss', 'appjs', 'favicon.ico'):
                    code = sanitize_session_code(potential_code)
    
    # 3. If no code found yet, it might be an empty code (root)
    if not code:
        code = ''
    
    # Get session info if code is valid
    active_files = []
    user_lang = DEFAULT_LANGUAGE
    native_lang = {'code': DEFAULT_LANGUAGE, 'name': 'English'}
    translations = DictWrapper(get_translations(DEFAULT_LANGUAGE))
    
    if code:
        code_dir = os.path.join(UPLOAD_DIR, code)
        if os.path.exists(code_dir):
            active_files = get_active_files(code_dir)
            user_lang = detect_language(request)
            native_lang = get_native_language_info(request)
            translations = DictWrapper(get_translations(user_lang))
    
    available_languages = get_available_languages(include_info=True)
    
    # Helper function to escape values for JavaScript (using JSON encoding)
    def js_escape(value):
        """Escape a value for safe use in JavaScript strings."""
        if value is None:
            return ''
        # Use JSON encoding which properly escapes special characters
        return json.dumps(str(value))[1:-1]  # Remove the surrounding quotes
    
    # Escape translation values for JavaScript
    js_translations = {}
    for key, value in translations._data.items():
        js_translations[key] = js_escape(value)
    
    response.content_type = 'application/javascript'
    # Get URL parts safely
    url_root = ''
    try:
        url_root = f"{request.urlparts.scheme}://{request.urlparts.netloc}"
    except AttributeError:
        # Fallback if urlparts is not available
        url_root = f"{request.environ.get('wsgi.url_scheme', 'http')}://{request.environ.get('HTTP_HOST', 'localhost')}"
    
    return template('app.js', code=js_escape(code), files=active_files,
                   lang=js_escape(user_lang),
                   native_lang_code=js_escape(native_lang['code']),
                   translations=DictWrapper(js_translations),
                   default_language=DEFAULT_LANGUAGE,
                   language_cookie_name=js_escape(LANGUAGE_COOKIE_NAME),
                   available_languages=available_languages,
                   available_languages_json=json.dumps(available_languages),
                   url_root=js_escape(url_root),
                   base_url=js_escape('' if BASE_URL == '/' else BASE_URL.rstrip('/') if BASE_URL.startswith('http://') or BASE_URL.startswith('https://') else BASE_URL),
                   max_size_mb=MAX_FILE_SIZE // (1024 * 1024),
                   max_storage_mb=MAX_STORAGE_SIZE // (1024 * 1024),
                   format_size=format_size,
                   umami_id=UMAMI_ID)

@app.route(f'{URL_PREFIX}/favicon.ico')
@app.route('/favicon.ico')
def serve_favicon():
    """Serve the static Favicon file."""
    set_security_headers()
    views_dir = os.path.join(os.path.dirname(__file__), 'views')
    return static_file('favicon.ico', root=views_dir)

@app.route('/<code>')
@app.route('/<code>/')
@app.route(f"{URL_PREFIX}/<code>" if URL_PREFIX else None)
@app.route(f"{URL_PREFIX}/<code>/" if URL_PREFIX else None)
def main_page(code):
    """Main page view."""
    set_security_headers()
    
    code = sanitize_session_code(code)
    
    # Prevent static files from being treated as session codes
    if not code or code in ('static', 'style.css', 'app.js', 'stylecss', 'appjs'):
        redirect(BASE_URL if BASE_URL else '/')
        
    code_dir = os.path.join(UPLOAD_DIR, code)
    
    # Cleanup on load - but we stay on this code regardless of cleanup result
    cleanup_session(code_dir)
    
    # Ensure the directory exists so the user can stay on this code
    if not os.path.exists(code_dir):
        os.makedirs(code_dir, exist_ok=True)

    active_files = get_active_files(code_dir)
    
    # Detect user's language
    user_lang = detect_language(request)
    native_lang = get_native_language_info(request)
    translations = DictWrapper(get_translations(user_lang))
    available_languages = get_available_languages(include_info=True)
    
    # Helper function to escape values for JavaScript (using JSON encoding)
    def js_escape(value):
        """Escape a value for safe use in JavaScript strings."""
        if value is None:
            return ''
        # Use JSON encoding which properly escapes special characters
        return json.dumps(str(value))[1:-1]  # Remove the surrounding quotes
    
    return template('index.html', code=code, files=active_files,
                   lang=user_lang,
                   native_lang=native_lang,
                   translations=translations,
                   default_language=DEFAULT_LANGUAGE,
                   language_cookie_name=LANGUAGE_COOKIE_NAME,
                   available_languages=available_languages,
                   available_languages_json=json.dumps(available_languages),
                   url_root=f"{request.urlparts.scheme}://{request.urlparts.netloc}",
                   base_url='' if BASE_URL == '/' else BASE_URL.rstrip('/') if BASE_URL.startswith('http://') or BASE_URL.startswith('https://') else BASE_URL,
                   max_size_mb=MAX_FILE_SIZE // (1024 * 1024),
                   max_storage_mb=MAX_STORAGE_SIZE // (1024 * 1024),
                   format_size=format_size,
                   umami_id=UMAMI_ID,
                   umami_url=UMAMI_URL,
                   contact_email=CONTACT_EMAIL,
                   company_name=COMPANY_NAME)

@app.post(f'{URL_PREFIX}/<code>/join')
@app.post('/<code>/join')
def join_session(code):
    """Handle client join request."""
    set_security_headers()
    
    code = sanitize_session_code(code)
    if not code or code in ('style.css', 'app.js', 'stylecss', 'appjs'):
        return {'success': False, 'error': 'Invalid code'}
    
    data = request.json or {}
    client_id = data.get('clientId')
    if not client_id:
        return {'success': False, 'error': 'Missing clientId'}
    
    # SECURITY: Validate client ID format
    if not validate_client_id(client_id):
        return {'success': False, 'error': 'Invalid client ID format'}
        
    code_dir = os.path.join(UPLOAD_DIR, code)
    if not os.path.exists(code_dir):
        return {'success': False, 'error': 'Session not found'}
        
    def update_join(state):
        # Check if we have an approved host before cleanup
        had_host = any(c['status'] == 'approved' for c in state['clients'].values())
        
        # Clean up stale clients
        cleanup_stale_clients(state)
        
        # Check if we still have an approved host
        has_host = any(c['status'] == 'approved' for c in state['clients'].values())
        
        # If last host disappeared, clear files
        if had_host and not has_host:
            clear_session_files(code_dir)

        ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
        if client_id not in state['clients']:
            trusted_ips = state.get('trusted_ips', {})
            
            # New client logic
            # If no active host exists OR this IP was successfully approved before
            ip = get_client_ip()
            is_trusted = isinstance(trusted_ips, dict) and ip in trusted_ips
            
            if not has_host or is_trusted:
                status = 'approved'
                has_host = True
                # Add to trusted IPs if not already there or update timestamp
                if isinstance(trusted_ips, dict):
                    state['trusted_ips'][ip] = time.time()
                else:
                    state['trusted_ips'] = {ip: time.time()}
            else:
                status = 'pending'
                
            state['clients'][client_id] = {
                'status': status,
                'last_seen': time.time(),
                'joined_at': time.time(),
                'ip': ip,
                'browser': request.get_header('User-Agent')
            }
            # Log join action
            log_action('JOIN', code, client_id, ip, {'status': status, 'trusted': ip in trusted_ips})
        else:
            # Existing client, update heartbeat
            state['clients'][client_id]['last_seen'] = time.time()
            # If session lost its host, promote existing client if they are next in line
            if not has_host:
                # Sort by entry or just pick first available to be deterministic
                # For simplicity, if NO host exists, current client becomes host
                clear_session_files(code_dir) # Safety double-check
                state['clients'][client_id]['status'] = 'approved'

                # Record IP as trusted
                client_ip = state['clients'][client_id].get('ip') or ip
                if client_ip:
                    if not isinstance(state.get('trusted_ips'), dict):
                        state['trusted_ips'] = {}
                    state['trusted_ips'][client_ip] = time.time()
    state = update_session_state(code_dir, update_join)
    return {'success': True, 'status': state['clients'][client_id]['status']}

@app.post(f'{URL_PREFIX}/<code>/heartbeat')
@app.post('/<code>/heartbeat')
def heartbeat(code):
    """Update presence and get session state."""
    set_security_headers()
    
    code = sanitize_session_code(code)
    if not code or code in ('style.css', 'app.js', 'stylecss', 'appjs'):
        return {'success': False, 'error': 'Invalid code'}
        
    data = request.json or {}
    client_id = data.get('clientId')
    
    if not client_id:
        return {'success': False, 'error': 'Missing clientId'}
    
    # SECURITY: Validate client ID format
    if not validate_client_id(client_id):
        return {'success': False, 'error': 'Invalid client ID format'}
        
    code_dir = os.path.join(UPLOAD_DIR, code)
    if not os.path.exists(code_dir):
        return {'success': False, 'error': 'Session not found'}
        
    def update_heartbeat(state):
        # Check host status
        had_host = any(c['status'] == 'approved' for c in state['clients'].values())
        cleanup_stale_clients(state)
        has_host = any(c['status'] == 'approved' for c in state['clients'].values())
        
        # If client was lost in state (server restart), re-add
        if client_id not in state['clients']:
            ip = get_client_ip()
            trusted_ips = state.get('trusted_ips', {})
            is_trusted = isinstance(trusted_ips, dict) and ip in trusted_ips
            
            # Auto-approve if no host exists OR IP is trusted
            if not has_host or is_trusted:
                status = 'approved'
                if not isinstance(state.get('trusted_ips'), dict):
                    state['trusted_ips'] = {}
                state['trusted_ips'][ip] = time.time()
            else:
                status = 'pending'
                
            state['clients'][client_id] = {
                'status': status, 
                'last_seen': time.time(),
                'ip': ip,
                'browser': request.get_header('User-Agent')
            }
        else:
            # Update last seen
            state['clients'][client_id]['last_seen'] = time.time()
            
            # PROMOTION LOGIC: If all hosts are gone, promote this client
            if not has_host:
                # Security: Clear previous host's files
                clear_session_files(code_dir)
                state['clients'][client_id]['status'] = 'approved'
                
                # Record IP as trusted
                ip = state['clients'][client_id].get('ip') or request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
                if ip:
                    if not isinstance(state.get('trusted_ips'), dict):
                        state['trusted_ips'] = {}
                    state['trusted_ips'][ip] = time.time()
                    
    state = update_session_state(code_dir, update_heartbeat)

    my_status = state['clients'][client_id]['status']
    
    # If I am approved, info about pending requests
    pending_requests = []
    if my_status == 'approved':
        for cid, cdata in state['clients'].items():
            if cdata['status'] == 'pending':
                pending_requests.append({
                    'clientId': cid,
                    'joined_at': cdata.get('joined_at', 0),
                    'ip': cdata.get('ip', 'Unknown'),
                    'browser': cdata.get('browser', 'Unknown')
                })
    
    return {
        'success': True,
        'status': my_status,
        'pending_requests': pending_requests
    }

@app.post(f'{URL_PREFIX}/<code>/approve')
@app.post('/<code>/approve')
def approve_client(code):
    """Approve or reject a client."""
    set_security_headers()
    
    code = sanitize_session_code(code)
    if not code or code in ('style.css', 'app.js', 'stylecss', 'appjs'):
        return {'success': False, 'error': 'Invalid code'}
    data = request.json or {}
    host_id = data.get('clientId')
    target_id = data.get('targetId')
    decision = data.get('decision') # 'approve' or 'reject'
    
    if not all([code, host_id, target_id, decision]):
        return {'success': False, 'error': 'Missing parameters'}
    
    # SECURITY: Validate client ID formats
    if not validate_client_id(host_id) or not validate_client_id(target_id):
        return {'success': False, 'error': 'Invalid client ID format'}
        
    code_dir = os.path.join(UPLOAD_DIR, code)
    
    update_result = [None]
    def update_approval_v2(state):
        if not is_client_approved(state, host_id):
            update_result[0] = 'unauthorized'
            return
        if target_id not in state['clients']:
            update_result[0] = 'not_found'
            return
            
        if decision == 'approve':
            state['clients'][target_id]['status'] = 'approved'
            ip = state['clients'][target_id].get('ip')
            if ip:
                if not isinstance(state.get('trusted_ips'), dict):
                    state['trusted_ips'] = {}
                state['trusted_ips'][ip] = time.time()
        else:
            state['clients'][target_id]['status'] = 'rejected'
        update_result[0] = 'success'

    update_session_state(code_dir, update_approval_v2)
    
    if update_result[0] == 'success':
        return {'success': True}
    elif update_result[0] == 'unauthorized':
        return {'success': False, 'error': 'Unauthorized'}
    else:
        return {'success': False, 'error': 'Target client not found'}
        
    return {'success': False, 'error': 'Target client not found'}

@app.post(f'{URL_PREFIX}/<code>/upload')
@app.post('/<code>/upload')
def upload_file(code):
    """Handle multiple file uploads."""
    set_security_headers()
    
    # Get user language for error messages
    user_lang = detect_language(request)
    translations = get_translations(user_lang)
    
    code = sanitize_session_code(code)
    if not code or code in ('style.css', 'app.js', 'stylecss', 'appjs'):
        response.status = 400
        return {'success': False, 'error': 'Invalid code'}
    
    # Check Client Approval
    client_id = request.forms.get('clientId')
    
    # SECURITY: Validate client ID format
    if not validate_client_id(client_id):
        response.status = 400
        return {'success': False, 'error': 'Invalid client ID format'}
    
    code_dir = os.path.join(UPLOAD_DIR, code)
    # Check Client Approval
    if not check_approval_or_auto_approve(code, client_id, code_dir):
        response.status = 403
        return {'success': False, 'error': translations.get('device_approval_required', 'Unauthorized: Device not approved')}

    uploads = request.files.getall('file')
    
    if not os.path.exists(code_dir):
        os.makedirs(code_dir, exist_ok=True)

    print(f"Uploading files for code: {code}")
    
    # Check origin country for file limit
    ip = get_client_ip()
    country = search_country(ip)
    is_restricted = country in RESTRICTED_COUNTRIES
    file_limit = MAX_FILES_RESTRICTED if is_restricted else MAX_FILES_NORMAL
    
    existing_files = get_active_files(code_dir)
    if len(existing_files) + len(uploads) > file_limit:
        mode_str = '제한' if is_restricted else '일반' if user_lang == 'ko' else 'restricted' if is_restricted else 'normal'
        error_msg = translations.get('file_count_exceeded', 'File count limit exceeded')
        error_msg = error_msg.replace('{{mode}}', mode_str).replace('{{limit}}', str(file_limit))
        return {'success': False, 'error': error_msg}

    uploaded_count = 0
    blocked_files = []
    too_large_files = []
    
    try:
        for upload in uploads:
            if not upload.raw_filename:
                continue
            
            # Check if file extension is blocked
            is_blocked, blocked_ext = is_file_extension_blocked(upload.raw_filename)
            if is_blocked:
                blocked_files.append(f"{upload.raw_filename} (.{blocked_ext})")
                continue
                
            normalized_filename = normalize_filename(upload.raw_filename)
            # Skip files with invalid/sanitized filenames (path traversal attempts)
            if not normalized_filename:
                print(f"Invalid filename skipped: {upload.raw_filename}")
                continue
            
            filepath = os.path.join(code_dir, normalized_filename)
            
            # Check individual file size
            upload.file.seek(0, 2)
            actual_size = upload.file.tell()
            upload.file.seek(0)
            
            if actual_size > MAX_FILE_SIZE:
                 too_large_files.append(f"{upload.raw_filename} ({actual_size // (1024*1024)}MB)")
                 continue

            # Check total session size
            current_total = get_session_size(code_dir)
            if current_total + actual_size > MAX_STORAGE_SIZE:
                print(f"Storage limit exceeded for session {code}: {current_total + actual_size} bytes")
                error_msg = translations.get('storage_limit_exceeded', 'Storage limit exceeded')
                error_msg = error_msg.replace('{{max_mb}}', str(MAX_STORAGE_SIZE // (1024*1024)))
                return {'success': False, 'error': error_msg}

            upload.save(filepath, overwrite=True)
            uploaded_count += 1
            print(f"Saved file: {normalized_filename}")
            
            # Log upload action
            file_hash = calculate_file_hash(filepath)
            ip = get_client_ip()
            log_action('UPLOAD', code, client_id, ip, {
                'filename': normalized_filename,
                'size': actual_size,
                'hash': file_hash
            })
    except Exception as e:
        print(f"ERROR: Upload failed for code {code}: {str(e)}")
        import traceback
        traceback.print_exc()
        response.status = 500
        return {'success': False, 'error': str(e)}

    response.set_header('Content-Type', 'application/json')
    
    # Return error if all files were blocked or too large
    if uploaded_count == 0 and (blocked_files or too_large_files):
        error_parts = []
        if blocked_files:
            blocked_ext_label = translations.get('blocked_extension', 'Blocked file extension')
            error_parts.append(f"{blocked_ext_label}: {', '.join(blocked_files)}")
        if too_large_files:
            file_size_label = translations.get('file_size_exceeded', 'File size exceeded')
            error_parts.append(f"{file_size_label}: {', '.join(too_large_files)}")
        return {'success': False, 'error': '\n'.join(error_parts)}
    
    if uploaded_count == 0:
        print(f"WARNING: No files were successfully saved for upload request in code {code}")
    
    return {'success': True, 'count': uploaded_count}

@app.post(f'{URL_PREFIX}/<code>/delete_all')
@app.post('/<code>/delete_all')
def delete_all_files(code):
    """Delete all files in a session."""
    set_security_headers()
    
    code = sanitize_session_code(code)
    if not code or code in ('style.css', 'app.js', 'stylecss', 'appjs'):
        return {'success': False, 'error': 'Invalid code'}
    
    code_dir = os.path.join(UPLOAD_DIR, code)
    
    # Check Client Approval
    client_id = request.forms.get('clientId') or request.json.get('clientId')
    
    # SECURITY: Validate client ID format
    if not validate_client_id(client_id):
        response.status = 400
        return {'success': False, 'error': 'Invalid client ID format'}
    
    # Check Client Approval
    if not check_approval_or_auto_approve(code, client_id, code_dir):
        response.status = 403
        return {'success': False, 'error': 'Unauthorized'}

    if os.path.exists(code_dir):
        for filename in os.listdir(code_dir):
            filepath = os.path.join(code_dir, filename)
            if os.path.isfile(filepath):
                try:
                    os.remove(filepath)
                except OSError:
                    pass
    
    # Log delete action
    ip = get_client_ip()
    log_action('DELETE_ALL', code, client_id, ip, {'count': len(os.listdir(code_dir)) if os.path.exists(code_dir) else 0})

    response.set_header('Content-Type', 'application/json')
    return {'success': True}

@app.post(f'{URL_PREFIX}/<code>/text-upload')
@app.post('/<code>/text-upload')
def upload_text(code):
    """Handle direct text input upload."""
    set_security_headers()
    
    # Get user language for error messages
    user_lang = detect_language(request)
    translations = get_translations(user_lang)
    
    code = sanitize_session_code(code)
    if not code or code in ('style.css', 'app.js', 'stylecss', 'appjs'):
        response.status = 400
        return {'success': False, 'error': 'Invalid code'}
    
    data = request.json
    if not data:
        return {'success': False, 'error': 'No data'}
    
    # Check Client Approval
    client_id = data.get('clientId')
    
    # SECURITY: Validate client ID format
    if not validate_client_id(client_id):
        response.status = 400
        return {'success': False, 'error': 'Invalid client ID format'}
        
    code_dir = os.path.join(UPLOAD_DIR, code)
    # Check Client Approval
    if not check_approval_or_auto_approve(code, client_id, code_dir):
        response.status = 403
        return {'success': False, 'error': translations.get('device_approval_required', 'Unauthorized')}

    try:
        if 'text' not in data:
            return {'success': False, 'error': translations.get('enter_content', 'No content provided')}
        
        content = data.get('text', '')
        if not content.strip():
            return {'success': False, 'error': translations.get('enter_content', 'No recognizable text')}
            
        # Check origin country for file limit
        ip = get_client_ip()
        country = search_country(ip)
        is_restricted = country in RESTRICTED_COUNTRIES
        file_limit = MAX_FILES_RESTRICTED if is_restricted else MAX_FILES_NORMAL
        
        existing_files = get_active_files(code_dir)
        if len(existing_files) + 1 > file_limit:
            mode_str = '제한' if is_restricted else '일반' if user_lang == 'ko' else 'restricted' if is_restricted else 'normal'
            error_msg = translations.get('file_count_exceeded', 'File count limit exceeded')
            error_msg = error_msg.replace('{{mode}}', mode_str).replace('{{limit}}', str(file_limit))
            return {'success': False, 'error': error_msg}

        # Naming logic: first 10 characters of the first line
        lines = content.strip().split('\n')
        first_line = lines[0].strip()
        filename_base = first_line[:10].strip() or "text_input"
        
        # Sanitize base name to remove problematic characters for filenames
        filename_base = re.sub(r'[\\/*?:"<>|]', '_', filename_base)
        
        if not os.path.exists(code_dir):
            os.makedirs(code_dir, exist_ok=True)
            
        target_filename = f"{filename_base}.txt"
        normalized_filename = normalize_filename(target_filename)
        filepath = os.path.join(code_dir, normalized_filename)
        
        # Logic: Overwrite if content is same, create different file if different
        if os.path.exists(filepath):
            with open(filepath, 'r', encoding='utf-8') as f:
                existing_content = f.read()
            
            if existing_content != content:
                # Generate a unique filename
                counter = 1
                while True:
                    new_filename = f"{filename_base} ({counter}).txt"
                    normalized_new = normalize_filename(new_filename)
                    new_filepath = os.path.join(code_dir, normalized_new)
                    if not os.path.exists(new_filepath):
                        filepath = new_filepath
                        break
                    else:
                        # If this one also exists, check its content
                        with open(new_filepath, 'r', encoding='utf-8') as f:
                            if f.read() == content:
                                filepath = new_filepath # Overwrite this one
                                break
                    counter += 1
        
        # Size validation
        content_bytes = content.encode('utf-8')
        actual_size = len(content_bytes)
        
        if actual_size > MAX_FILE_SIZE:
            error_msg = translations.get('file_too_large', 'File is too large')
            error_msg = error_msg.replace('{{max_size_mb}}', str(MAX_FILE_SIZE // (1024*1024)))
            return {'success': False, 'error': error_msg}
            
        current_total = get_session_size(code_dir)
        if current_total + actual_size > MAX_STORAGE_SIZE:
             error_msg = translations.get('storage_limit_exceeded', 'Storage limit exceeded')
             error_msg = error_msg.replace('{{max_mb}}', str(MAX_STORAGE_SIZE // (1024*1024)))
             return {'success': False, 'error': error_msg}

        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)
            
        # Log text upload
        file_hash = calculate_file_hash(filepath)
        ip = get_client_ip()
        log_action('UPLOAD_TEXT', code, client_id, ip, {
            'filename': os.path.basename(filepath),
            'size': actual_size,
            'hash': file_hash
        })

        return {'success': True, 'filename': os.path.basename(filepath)}
        
    except Exception as e:
        print(f"ERROR: Text upload failed: {str(e)}")
        response.status = 500
        return {'success': False, 'error': str(e)}

@app.get(f'{URL_PREFIX}/<code>/download/<filename>')
@app.get('/<code>/download/<filename>')
def download(code, filename):
    """Download a file."""
    set_security_headers()
    
    code = sanitize_session_code(code)
    if not code or code in ('style.css', 'app.js', 'stylecss', 'appjs'):
        abort(404, "Invalid session")
    
    code_dir = os.path.join(UPLOAD_DIR, code)

    client_id = request.query.get('clientId')
    # Auto-approve solo users to be robust against race conditions
    if not check_approval_or_auto_approve(code, client_id, code_dir):
        abort(403, "Access denied: Device not approved")

    # Sanitize filename to prevent path traversal
    safe_filename = sanitize_filename(filename)
    if not safe_filename:
        abort(403, "Invalid filename")
    
    cleanup_session(code_dir)
    
    # Validate the final path is within the code directory
    safe_path = os.path.abspath(os.path.join(code_dir, safe_filename))
    if not safe_path.startswith(os.path.abspath(code_dir) + os.sep):
        abort(403, "Access denied")
    
    response.set_header('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0')
    
    # Log download action
    ip = get_client_ip()
    log_action('DOWNLOAD', code, client_id, ip, {'filename': safe_filename})
    
    return static_file(safe_filename, root=code_dir, download=True)



if __name__ == '__main__':
    app.run(host='0.0.0.0', port=PORT, debug=DEBUG, reloader=DEBUG)
