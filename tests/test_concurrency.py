#!/usr/bin/env python3
import unittest
import os
import sys
import shutil
import tempfile
import time
import threading
from concurrent.futures import ThreadPoolExecutor

# Add project root to path so 'src' can be imported as a package
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src import session

class TestConcurrency(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        os.makedirs(self.test_dir, exist_ok=True)

    def tearDown(self):
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)

    def test_session_state_file_locking(self):
        """Test that session state updates are safe under high concurrency."""
        code_dir = self.test_dir
        
        # Initialize state
        state = session.load_session_state(code_dir)
        state['clients']['initial'] = {'status': 'approved', 'last_seen': time.time()}
        session.save_session_state(code_dir, state)

        num_threads = 20
        iterations = 50

        def update_task(client_id):
            for i in range(iterations):
                # Use the new atomic update function
                def callback(s):
                    if 'clients' not in s:
                        s['clients'] = {}
                    s['clients'][client_id] = {
                        'status': 'approved', 
                        'last_seen': time.time(),
                        'iteration': i
                    }
                session.update_session_state(code_dir, callback)
                # Small sleep to increase chance of collisions
                time.sleep(0.001)

        threads = []
        for i in range(num_threads):
            cid = f"client_{i}"
            t = threading.Thread(target=update_task, args=(cid,))
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        # Final check
        final_state = session.load_session_state(code_dir)
        
        # Verify no data corruption - all clients should be present
        for i in range(num_threads):
            cid = f"client_{i}"
            self.assertIn(cid, final_state['clients'], f"Client {cid} was lost during concurrent updates")
            self.assertEqual(final_state['clients'][cid]['iteration'], iterations - 1)

    def test_concurrent_save_with_lock(self):
        """Test specifically if save_session_state handles atomic writes correctly."""
        code_dir = self.test_dir
        
        def rapid_save():
            for i in range(100):
                s = session.load_session_state(code_dir)
                s['last_iteration'] = i
                session.save_session_state(code_dir, s)

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(rapid_save) for _ in range(5)]
            for future in futures:
                future.result()

        # If data was corrupted (e.g. truncated but not written due to race), 
        # load_session_state would return default_state.
        final_state = session.load_session_state(code_dir)
        self.assertIn('clients', final_state)
        self.assertIn('last_iteration', final_state)

if __name__ == '__main__':
    unittest.main()
