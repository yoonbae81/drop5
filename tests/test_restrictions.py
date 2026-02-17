#!/usr/bin/env python3
import unittest
import os
import sys
from unittest.mock import MagicMock, patch

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

try:
    from bottle import request, response
    from main import upload_file, upload_text
except ImportError:
    pass

class TestRegionRestrictions(unittest.TestCase):
    def setUp(self):
        # Setup common mocks
        self.code = 'testcode'
        self.client_id = 'test-client-id'
        
    @patch('main.get_client_ip')
    @patch('main.search_country')
    @patch('main.get_active_files')
    @patch('main.check_approval_or_auto_approve')
    @patch('main.validate_client_id')
    @patch('main.sanitize_session_code')
    @patch('main.request')
    def test_upload_file_limit_normal_region(self, mock_request, mock_sanitize, mock_validate, mock_approve, mock_get_files, mock_search, mock_get_ip):
        # Setup
        mock_sanitize.return_value = self.code
        mock_validate.return_value = True
        mock_approve.return_value = True
        mock_get_ip.return_value = '1.1.1.1'
        mock_search.return_value = 'KR' # Normal region
        
        # Test Case: 29 existing files, trying to upload 1 (Total 30, should be okay)
        mock_get_files.return_value = ['f'] * 29
        mock_file = MagicMock()
        mock_file.raw_filename = 'test.txt'
        mock_file.file.tell.return_value = 100 # Mock actual_size
        mock_request.files.getall.return_value = [mock_file]
        mock_request.forms.get.return_value = self.client_id
        
        with patch('main.RESTRICTED_COUNTRIES', ['RU', 'CN']), \
             patch('main.MAX_FILES_NORMAL', 30), \
             patch('main.MAX_FILES_RESTRICTED', 5), \
             patch('os.makedirs'), \
             patch('os.path.exists', return_value=True):
            
            # This should proceed past the count check
            # We mock the rest of the function to avoid actual file operations
            with patch('main.get_session_size', return_value=0):
                result = upload_file(self.code)
                # If it didn't return the "File count limit exceeded" error, it's a pass for this check
                if isinstance(result, dict) and result.get('error'):
                    self.assertNotIn('파일 개수 제한 초과', result['error'])

    @patch('main.get_client_ip')
    @patch('main.search_country')
    @patch('main.get_active_files')
    @patch('main.check_approval_or_auto_approve')
    @patch('main.validate_client_id')
    @patch('main.sanitize_session_code')
    @patch('main.request')
    def test_upload_file_limit_restricted_region(self, mock_request, mock_sanitize, mock_validate, mock_approve, mock_get_files, mock_search, mock_get_ip):
        # Setup
        mock_sanitize.return_value = self.code
        mock_validate.return_value = True
        mock_approve.return_value = True
        mock_get_ip.return_value = '2.2.2.2'
        mock_search.return_value = 'RU' # Restricted region
        
        # Test Case: 5 existing files, trying to upload 1 (Total 6, should be blocked)
        mock_get_files.return_value = ['f'] * 5
        mock_request.files.getall.return_value = [MagicMock(raw_filename='test.txt')]
        mock_request.forms.get.return_value = self.client_id
        
        with patch('main.RESTRICTED_COUNTRIES', ['RU', 'CN']), \
             patch('main.MAX_FILES_NORMAL', 30), \
             patch('main.MAX_FILES_RESTRICTED', 5), \
             patch('os.makedirs'), \
             patch('os.path.exists', return_value=True):
            
            result = upload_file(self.code)
            self.assertEqual(result['success'], False)
            self.assertIn('파일 개수 제한 초과', result['error'])
            self.assertIn('최대 5개', result['error'])

    @patch('main.get_client_ip')
    @patch('main.search_country')
    @patch('main.get_active_files')
    @patch('main.check_approval_or_auto_approve')
    @patch('main.validate_client_id')
    @patch('main.sanitize_session_code')
    @patch('main.request')
    def test_upload_text_limit_restricted_region(self, mock_request, mock_sanitize, mock_validate, mock_approve, mock_get_files, mock_search, mock_get_ip):
        # Setup
        mock_sanitize.return_value = self.code
        mock_validate.return_value = True
        mock_approve.return_value = True
        mock_get_ip.return_value = '2.2.2.2'
        mock_search.return_value = 'RU' # Restricted region
        
        # Test Case: 5 existing files, trying to upload text (Total 6, should be blocked)
        mock_get_files.return_value = ['f'] * 5
        mock_request.json = {'text': 'some text', 'clientId': self.client_id}
        
        with patch('main.RESTRICTED_COUNTRIES', ['RU', 'CN']), \
             patch('main.MAX_FILES_NORMAL', 30), \
             patch('main.MAX_FILES_RESTRICTED', 5), \
             patch('os.makedirs'), \
             patch('os.path.exists', return_value=True):
            
            result = upload_text(self.code)
            self.assertEqual(result['success'], False)
            self.assertIn('파일 개수 제한 초과', result['error'])
            self.assertIn('최대 5개', result['error'])

if __name__ == '__main__':
    unittest.main()
