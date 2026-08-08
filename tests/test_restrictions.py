#!/usr/bin/env python3
import os
import sys
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from main import upload_file, upload_text


class TestUploadLimits(unittest.TestCase):
    def setUp(self):
        self.code = 'testcode'

    @patch('main.get_active_files', return_value=['f'] * 30)
    @patch('main.sanitize_session_code', return_value='testcode')
    @patch('main.request')
    def test_file_upload_limit_is_shared_across_regions(
        self, mock_request, _mock_sanitize, _mock_get_files
    ):
        mock_request.json = None
        mock_request.files.getall.return_value = [MagicMock(raw_filename='test.txt')]
        mock_request.forms.get.return_value = None

        with (
            patch('main.MAX_FILES', 30),
            patch('os.path.exists', return_value=True),
            patch('os.makedirs'),
        ):
            result = upload_file(self.code)

        self.assertEqual(result['success'], False)
        self.assertIn('파일 개수 제한 초과', result['error'])
        self.assertIn('최대 30개', result['error'])

    @patch('main.get_active_files', return_value=['f'] * 30)
    @patch('main.sanitize_session_code', return_value='testcode')
    @patch('main.request')
    def test_text_upload_limit_is_shared_across_regions(
        self, mock_request, _mock_sanitize, _mock_get_files
    ):
        mock_request.json = {'content': 'some text'}

        with (
            patch('main.MAX_FILES', 30),
            patch('os.path.exists', return_value=True),
            patch('os.makedirs'),
        ):
            result = upload_text(self.code)

        self.assertEqual(result['success'], False)
        self.assertIn('파일 개수 제한 초과', result['error'])
        self.assertIn('최대 30개', result['error'])


if __name__ == '__main__':
    unittest.main()
