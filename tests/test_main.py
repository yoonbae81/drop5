import unittest
import sys
import os
import shutil
import time

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
        
        # Directory mtime was updated when file was removed, so we need to set it to past again
        # to test directory removal logic
        os.utime(code_dir, (past, past))
        main.cleanup_session(code_dir)
        
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

    def test_check_approval_or_auto_approve(self):
        """Test the atomic auto-approval logic"""
        code = "atomic1"
        code_dir = os.path.join(self.test_upload_dir, code)
        client_id = "test_client_1"
        
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

if __name__ == '__main__':
    unittest.main()
