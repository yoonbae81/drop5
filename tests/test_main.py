import unittest
import sys
import os
import shutil
import time
from unittest.mock import patch

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

import main

class TestMain(unittest.TestCase):
    """Test cases for main.py"""

    def setUp(self):
        """Set up test fixtures.
        We manually override main configuration here instead of loading .env
        to ensure tests are isolated and don't depend on local developer settings.
        """
        self.test_upload_dir = os.path.abspath('test_files')
        if not os.path.exists(self.test_upload_dir):
            os.makedirs(self.test_upload_dir)
        
        # Override module constants for testing
        main.UPLOAD_DIR = self.test_upload_dir
        main.FILE_TIMEOUT = 1 # 1 second for fast testing

    def tearDown(self):
        """Clean up after tests"""
        if os.path.exists(self.test_upload_dir):
            shutil.rmtree(self.test_upload_dir)

    def test_generate_code(self):
        """Test code generation uniqueness"""
        codes = set()
        for _ in range(10):
            code = main.generate_code()
            self.assertEqual(len(code), 5)
            self.assertTrue(code.isalnum())
            self.assertNotIn(code, codes)
            codes.add(code)

    def test_cleanup_session_removes_expired(self):
        """Test that cleanup_session removes expired files"""
        code = "12345"
        code_dir = os.path.join(self.test_upload_dir, code)
        os.makedirs(code_dir)
        
        file_path = os.path.join(code_dir, 'test.txt')
        
        with open(file_path, 'w') as f:
            f.write('hello')
            
        # Set mtime to past (beyond 1 second timeout set in setUp)
        # and beyond 300 second session timeout
        past = time.time() - 600
        os.utime(file_path, (past, past))
        os.utime(code_dir, (past, past))
        
        main.cleanup_session(code_dir)
        
        self.assertFalse(os.path.exists(file_path))
        
        # The hardened cleanup removes the now-empty session immediately.
        self.assertFalse(os.path.exists(code_dir))

    def test_cleanup_session_keeps_active(self):
        """Test that cleanup_session keeps active files"""
        code = "54321"
        code_dir = os.path.join(self.test_upload_dir, code)
        os.makedirs(code_dir)
        
        file_path = os.path.join(code_dir, 'test.txt')
        
        with open(file_path, 'w') as f:
            f.write('hello')
            
        main.cleanup_session(code_dir)
        
        self.assertTrue(os.path.exists(file_path))
        self.assertTrue(os.path.exists(code_dir))

    def test_cleanup_session_removes_expired_session_dir_immediately(self):
        """Test that a session directory is removed after expired files are deleted."""
        code = "77777"
        code_dir = os.path.join(self.test_upload_dir, code)
        os.makedirs(code_dir)
        
        file_path = os.path.join(code_dir, 'old.txt')
        with open(file_path, 'w') as f:
            f.write('expired')
            
        past = time.time() - 600
        os.utime(file_path, (past, past))
        
        main.cleanup_session(code_dir)
        
        self.assertFalse(os.path.exists(file_path))
        self.assertFalse(os.path.exists(code_dir))

    def test_cleanup_session_removes_stale_empty_session_dir(self):
        """Empty sessions must not survive forever just because no file expired."""
        code_dir = os.path.join(self.test_upload_dir, 'empty-stale')
        os.makedirs(code_dir)
        past = time.time() - 600
        os.utime(code_dir, (past, past))

        from src import session as session_module
        with patch.object(session_module, 'FILE_TIMEOUT', 1):
            session_module.cleanup_session(code_dir)

        self.assertFalse(os.path.exists(code_dir))

    def test_check_approval_or_auto_approve(self):
        """Test the atomic auto-approval logic"""
        code = "atomic1"
        code_dir = os.path.join(self.test_upload_dir, code)
        client_id = "test_client_1"
        os.makedirs(code_dir)
        
        # 1. First user should be auto-approved (IP: 1.1.1.1)
        from bottle import request
        with unittest.mock.patch.dict(request.environ, {'REMOTE_ADDR': '1.1.1.1'}):
            result = main.check_approval_or_auto_approve(code, client_id, code_dir)
            self.assertTrue(result)
        
        # Verify state
        from src.session import load_session_state
        state = load_session_state(code_dir)
        self.assertEqual(state['clients'][client_id]['status'], 'approved')
        self.assertIn('1.1.1.1', state.get('trusted_ips', {}))
        
        # 2. Second user from DIFFERENT IP should NOT be auto-approved
        client_id_2 = "test_client_2"
        with unittest.mock.patch.dict(request.environ, {'REMOTE_ADDR': '2.2.2.2'}):
            result_2 = main.check_approval_or_auto_approve(code, client_id_2, code_dir)
            self.assertFalse(result_2)
        
        state = load_session_state(code_dir)
        self.assertNotIn(client_id_2, state['clients'])

    def test_approved_client_auth_check_avoids_state_write(self):
        code = "cached1"
        code_dir = os.path.join(self.test_upload_dir, code)
        os.makedirs(code_dir)
        state = {
            'clients': {
                'test_client_1': {
                    'status': 'approved',
                    'last_seen': time.time(),
                }
            },
            'trusted_ips': {},
        }
        from src.session import save_session_state
        save_session_state(code_dir, state)

        with patch.object(main, 'update_session_state') as update:
            self.assertTrue(
                main.check_approval_or_auto_approve(
                    code, 'test_client_1', code_dir
                )
            )

        update.assert_not_called()

if __name__ == '__main__':
    unittest.main()
