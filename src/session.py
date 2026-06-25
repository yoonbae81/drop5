import os
import time
import glob
import shutil
import json
import fcntl
from src.config import UPLOAD_DIR, FILE_TIMEOUT
from src.utils import format_size

def get_session_size(code_dir, use_cache=True):
    """Calculate the total size of files in a session directory.

    Args:
        code_dir: Session directory path
        use_cache: If True, try to use cached value from session state (default: True)

    Returns:
        Total size in bytes
    """
    # Try cache first if enabled
    if use_cache:
        try:
            state = load_session_state(code_dir)
            cached_size = state.get('total_size')
            if cached_size is not None:
                # Verify cache is reasonably recent (within last hour)
                if time.time() - state.get('last_updated', 0) < 3600:
                    return cached_size
        except Exception:
            pass  # Fall back to direct calculation

    # Direct calculation
    total_size = 0
    if os.path.exists(code_dir):
        for filename in os.listdir(code_dir):
            filepath = os.path.join(code_dir, filename)
            if os.path.isfile(filepath):
                try:
                    total_size += os.path.getsize(filepath)
                except OSError:
                    pass

    # Update cache if we calculated directly
    if use_cache and total_size > 0:
        try:
            def update_cache(state):
                state['total_size'] = total_size
            update_session_state(code_dir, update_cache)
        except Exception:
            pass  # Cache update is optional

    return total_size

def cleanup_session(code_dir):
    """Cleanup expired files and remove empty session directories.

    Performance optimized: Uses os.scandir() which caches stat information,
    reducing syscalls from multiple per file to ~1 syscall total.
    """
    if not os.path.exists(code_dir):
        return True

    now = time.time()
    files_active = False
    real_files_count = 0

    try:
        # Single scandir() call for both cleanup and empty check
        with os.scandir(code_dir) as entries:
            for entry in entries:
                # Skip session state file
                if entry.name == '.session.json':
                    continue

                # Skip hidden files (but still count them for directory removal logic)
                if entry.name.startswith('.'):
                    continue

                real_files_count += 1

                # Cleanup expired files
                if entry.is_file():
                    try:
                        stat = entry.stat()
                        if now - stat.st_mtime > FILE_TIMEOUT:
                            os.remove(entry.path)
                            real_files_count -= 1
                        else:
                            files_active = True
                    except OSError:
                        pass  # Ignore race conditions
    except OSError:
        return False

    # Remove session if empty and no active files
    if real_files_count == 0 and not files_active:
        # Only remove if directory has existed for at least 300 seconds (5 min)
        try:
            if now - os.path.getmtime(code_dir) > 300:
                shutil.rmtree(code_dir)
                return True
        except OSError:
            pass

    return False

def cleanup_all_sessions():
    """Scan and cleanup all expired sessions in the files directory.

    Performance optimized: Uses os.scandir() for both directory iteration
    and file iteration, reducing syscalls significantly.
    """
    if not os.path.exists(UPLOAD_DIR):
        return

    now = time.time()

    # Iterate through all session directories using scandir
    try:
        with os.scandir(UPLOAD_DIR) as session_entries:
            for session_entry in session_entries:
                if not session_entry.is_dir():
                    continue

                code_dir = session_entry.path

                try:
                    # Get directory mtime from cached scandir stat
                    dir_stat = session_entry.stat()
                    dir_mtime = dir_stat.st_mtime

                    # Clean expired files in this session
                    has_active_files = False
                    remaining_files_count = 0

                    with os.scandir(code_dir) as file_entries:
                        for file_entry in file_entries:
                            # Skip session state file
                            if file_entry.name == '.session.json':
                                continue

                            # Skip hidden files
                            if file_entry.name.startswith('.'):
                                continue

                            remaining_files_count += 1

                            if file_entry.is_file():
                                try:
                                    stat = file_entry.stat()
                                    if now - stat.st_mtime > FILE_TIMEOUT:
                                        os.remove(file_entry.path)
                                        remaining_files_count -= 1
                                    else:
                                        has_active_files = True
                                except OSError:
                                    pass

                    # Remove session directory if empty and no active files
                    if remaining_files_count == 0 and not has_active_files:
                        # Only remove if directory is old enough
                        if now - dir_mtime > 300:
                            try:
                                shutil.rmtree(code_dir)
                            except OSError:
                                pass
                except OSError:
                    pass
    except OSError:
        pass

def get_active_files(code_dir):
    """Helper to get list of active files in a directory.

    Performance optimized: Uses os.scandir() which caches stat information,
    reducing syscalls from ~3 per file (listdir+isfile+getmtime+getsize)
    to ~1 syscall per file (scandir internally does stat, cached in DirEntry).
    """
    active_files = []
    now = time.time()

    if os.path.exists(code_dir):
        files_with_time = []
        try:
            # os.scandir() is more efficient than os.listdir() + os.stat()
            # DirEntry objects cache stat results, avoiding redundant syscalls
            with os.scandir(code_dir) as entries:
                for entry in entries:
                    if entry.name == '.session.json':
                        continue
                    if entry.is_file():
                        try:
                            # entry.stat() returns cached stat data from scandir
                            stat = entry.stat()
                            files_with_time.append((entry.name, stat.st_mtime, stat.st_size))
                        except OSError:
                            continue
        except OSError:
            return active_files

        # Sort: most recent first
        files_with_time.sort(key=lambda x: x[1], reverse=True)

        for filename, mtime, file_size in files_with_time:
            expiry_time = mtime + FILE_TIMEOUT
            remaining = expiry_time - now

            if remaining > 0:
                active_files.append({
                    'name': filename,
                    'size': file_size,  # Already obtained from scandir stat cache
                    'formatted_size': format_size(file_size),
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
    # Reset cache after clearing files
    update_session_size_cache(code_dir, 0)


def update_session_size_cache(code_dir, delta_bytes, file_path=None, is_add=True):
    """Update the cached total size for a session.

    Args:
        code_dir: Session directory path
        delta_bytes: Size change in bytes (or absolute size if file_path provided)
        file_path: If provided, calculate delta from this file
        is_add: True if file was added, False if removed

    Returns:
        Updated total size
    """
    try:
        state = load_session_state(code_dir)
        current_total = state.get('total_size', 0)

        if file_path and os.path.exists(file_path):
            # Calculate delta from actual file
            actual_size = os.path.getsize(file_path)
            if is_add:
                # Add file size to cache
                new_total = current_total + actual_size
            else:
                # Remove file size from cache
                new_total = max(0, current_total - actual_size)
        else:
            # Use explicit delta
            if is_add:
                new_total = current_total + delta_bytes
            else:
                new_total = max(0, current_total - delta_bytes)

        def update_cache(s):
            s['total_size'] = new_total
        update_session_state(code_dir, update_cache)
        return new_total
    except Exception as e:
        print(f"Error updating size cache: {e}")
        return None
