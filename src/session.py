import os
import time
import glob
import shutil
import json
import fcntl
from src.config import UPLOAD_DIR, FILE_TIMEOUT
from src.utils import format_size

def get_session_size(code_dir):
    """Calculate the total size of files in a session directory."""
    total_size = 0
    if os.path.exists(code_dir):
        for filename in os.listdir(code_dir):
            filepath = os.path.join(code_dir, filename)
            if os.path.isfile(filepath):
                try:
                    total_size += os.path.getsize(filepath)
                except OSError:
                    pass
    return total_size

def cleanup_session(code_dir):
    """Cleanup expired files and remove empty session directories."""
    if not os.path.exists(code_dir):
        return True

    now = time.time()
    files_active = False

    # 1. Cleanup expired files
    for filepath in glob.glob(os.path.join(code_dir, '*')):
        if filepath.endswith('.timestamp') or filepath.endswith('.session.json'):
            continue
        
        if os.path.isfile(filepath):
            try:
                if now - os.path.getmtime(filepath) > FILE_TIMEOUT:
                    os.remove(filepath)
                else:
                    files_active = True
            except OSError:
                pass # Ignore race conditions

    # 2. Remove session if empty or only contains hidden files/metadata
    try:
        all_entries = os.listdir(code_dir)
        # Filter out hidden files like .csrf_token and our session file
        real_files = [f for f in all_entries if not f.startswith('.') and f != '.session.json']
        
        if not real_files and not files_active:
             # Only remove if directory has existed for at least 300 seconds (5 min)
             if now - os.path.getmtime(code_dir) > 300:
                 shutil.rmtree(code_dir)
                 return True
    except OSError:
        pass
            
    return False

def cleanup_all_sessions():
    """Scan and cleanup all expired sessions in the files directory."""
    if not os.path.exists(UPLOAD_DIR):
        return
    
    now = time.time()
    
    # Iterate through all session directories
    for code_dir in glob.glob(os.path.join(UPLOAD_DIR, '*')):
        if not os.path.isdir(code_dir):
            continue
            
        try:
            # Check if directory itself is old enough to be cleaned
            dir_mtime = os.path.getmtime(code_dir)
            
            # Clean expired files in this session
            has_active_files = False
            for filepath in glob.glob(os.path.join(code_dir, '*')):
                if filepath.endswith('.timestamp') or filepath.endswith('.session.json'):
                    continue
                
                if os.path.isfile(filepath):
                    try:
                        if now - os.path.getmtime(filepath) > FILE_TIMEOUT:
                            os.remove(filepath)
                        else:
                            has_active_files = True
                    except OSError:
                        pass
            
            # Remove session directory if empty or no active files
            remaining_files = [f for f in os.listdir(code_dir) if f != '.session.json'] if os.path.exists(code_dir) else []
            if not remaining_files and not has_active_files:
                # Only remove if directory is old enough
                if now - dir_mtime > 300:
                    try:
                        shutil.rmtree(code_dir)
                    except OSError:
                        pass
        except OSError:
            pass

def get_active_files(code_dir):
    """Helper to get list of active files in a directory."""
    active_files = []
    now = time.time()
    
    if os.path.exists(code_dir):
        # Sort by mtime descending (newest first)
        files_in_dir = os.listdir(code_dir)
        files_with_time = []
        for filename in files_in_dir:
            if filename == '.session.json':
                continue
            filepath = os.path.join(code_dir, filename)
            if os.path.isfile(filepath):
                try:
                    files_with_time.append((filename, os.path.getmtime(filepath)))
                except OSError:
                    continue
        
        # Sort: most recent first
        files_with_time.sort(key=lambda x: x[1], reverse=True)
        
        for filename, mtime in files_with_time:
            filepath = os.path.join(code_dir, filename)
            expiry_time = mtime + FILE_TIMEOUT
            remaining = expiry_time - now
            
            if remaining > 0:
                active_files.append({
                    'name': filename,
                    'size': os.path.getsize(filepath),
                    'formatted_size': format_size(os.path.getsize(filepath)),
                    'remaining_min': int(remaining // 60),
                    'remaining_sec': f"{int(remaining % 60):02d}",
                    'remaining_total': int(remaining)
                })
    return active_files

# --- Session State Management ---

def get_session_state_path(code_dir):
    return os.path.join(code_dir, '.session.json')

def load_session_state(code_dir):
    """Load session state from file with locking."""
    filepath = get_session_state_path(code_dir)
    default_state = {'clients': {}, 'trusted_ips': {}, 'last_updated': time.time()}
    
    if not os.path.exists(filepath):
        return default_state
        
    try:
        with open(filepath, 'r') as f:
            # Shared lock for reading
            fcntl.flock(f, fcntl.LOCK_SH)
            try:
                state = json.load(f)
                return state
            finally:
                fcntl.flock(f, fcntl.LOCK_UN)
    except (json.JSONDecodeError, OSError):
        return default_state

def update_session_state(code_dir, callback):
    """
    Atomic update for session state using an exclusive lock for the duration of the update.
    The callback receives the state dictionary and should modify it in-place.
    Returns the updated state.
    """
    filepath = get_session_state_path(code_dir)
    default_state = {'clients': {}, 'trusted_ips': {}, 'last_updated': time.time()}
    
    try:
        # Ensure parent directory exists
        if not os.path.exists(code_dir):
            os.makedirs(code_dir, exist_ok=True)
            
        mode = 'r+' if os.path.exists(filepath) else 'w+'
        with open(filepath, mode) as f:
            # Exclusive lock for the entire transaction (Load-Modify-Save)
            fcntl.flock(f, fcntl.LOCK_EX)
            try:
                state = default_state
                if os.path.getsize(filepath) > 0:
                    f.seek(0)
                    try:
                        state = json.load(f)
                    except json.JSONDecodeError:
                        state = default_state
                
                # Perform the update
                callback(state)
                state['last_updated'] = time.time()
                
                # Save
                f.truncate(0)
                f.seek(0)
                json.dump(state, f)
                f.flush()
                os.fsync(f.fileno())
                return state
            finally:
                fcntl.flock(f, fcntl.LOCK_UN)
    except OSError as e:
        print(f"Error updating session state: {e}")
        return default_state

def save_session_state(code_dir, state):
    """Save session state to file with locking. Uses r+ to avoid truncation before locking."""
    filepath = get_session_state_path(code_dir)
    state['last_updated'] = time.time()
    
    try:
        if not os.path.exists(code_dir):
            os.makedirs(code_dir, exist_ok=True)
            
        # Use r+ to open for read/write without truncation
        mode = 'r+' if os.path.exists(filepath) else 'w+'
        with open(filepath, mode) as f:
            # Exclusive lock for writing
            fcntl.flock(f, fcntl.LOCK_EX)
            try:
                if mode == 'r+':
                    f.truncate(0)
                    f.seek(0)
                json.dump(state, f)
                f.flush()
                # Ensure it's written to disk
                os.fsync(f.fileno())
            finally:
                fcntl.flock(f, fcntl.LOCK_UN)
    except OSError as e:
        print(f"Error saving session state: {e}")

def cleanup_stale_clients(state):
    """Remove clients inactive for > 30 seconds."""
    now = time.time()
    active_threshold = 300 # 5 minutes to accommodate large file uploads
    
    active_clients = {}
    changed = False
    
    for client_id, client_data in state.get('clients', {}).items():
        if now - client_data.get('last_seen', 0) < active_threshold:
            active_clients[client_id] = client_data
        else:
            changed = True
            print(f"[{time.strftime('%H:%M:%S')}] Client timed out: {client_id} (Status: {client_data.get('status')})")
            
    state['clients'] = active_clients
    
    state['clients'] = active_clients
    return changed

def is_client_approved(state, client_id):
    """Check if a specific client is approved."""
    if not client_id:
        return False
    client = state.get('clients', {}).get(client_id)
    return client and client.get('status') == 'approved'

def clear_session_files(code_dir):
    """Remove all files in session directory except state file."""
    if not os.path.exists(code_dir):
        return
    import shutil
    print(f"[{time.strftime('%H:%M:%S')}] Clearing files for session reset: {code_dir}")
    for filename in os.listdir(code_dir):
        if filename == '.session.json':
            continue
        filepath = os.path.join(code_dir, filename)
        try:
            if os.path.isfile(filepath) or os.path.islink(filepath):
                os.unlink(filepath)
                print(f"  Deleted file: {filename}")
            elif os.path.isdir(filepath):
                shutil.rmtree(filepath)
                print(f"  Deleted dir: {filename}")
        except Exception as e:
            print(f"  Error deleting {filename}: {e}")
