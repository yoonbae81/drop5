import io
import os
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

import main


class TestUploadRouting(unittest.TestCase):
    def test_dotted_session_route_is_rejected_before_handlers(self):
        request = MagicMock()
        request.path = '/imgphp.php'
        response = MagicMock()

        with (
            patch.object(main, 'request', request),
            patch.object(main, 'response', response),
            patch.object(main, 'cleanup_all_sessions'),
        ):
            result = main.reject_dotted_session_routes()

        self.assertEqual(result, {'error': 'Invalid route'})
        self.assertEqual(response.status, 400)

    def test_invalid_code_with_extension_is_rejected_400(self):
        mock_response = MagicMock()
        request = MagicMock()

        with (
            patch.object(main, 'request', request),
            patch.object(main, 'response', mock_response),
            patch.object(main, 'set_security_headers'),
        ):
            result = main.files_api('payload.json')

        self.assertEqual(result, {'success': False, 'error': 'Invalid code'})
        self.assertEqual(mock_response.status, 400)

    def test_delete_all_preserves_session_state(self):
        with tempfile.TemporaryDirectory() as upload_dir:
            code_dir = os.path.join(upload_dir, 'session')
            os.makedirs(code_dir)
            state_path = os.path.join(code_dir, '.session.json')
            with open(state_path, 'w', encoding='utf-8') as state_file:
                state_file.write('{}')

            request = MagicMock()
            request.forms.get.side_effect = lambda key: 'client-123456' if key == 'clientId' else None
            request.json = None

            with (
                patch.object(main, 'UPLOAD_DIR', upload_dir),
                patch.object(main, 'request', request),
                patch.object(main, 'check_approval_or_auto_approve', return_value=True),
                patch.object(main, 'log_action'),
                patch.object(main, 'update_session_size_cache'),
            ):
                result = main.delete_all_files('session')

            self.assertEqual(result, {'success': True})
            self.assertTrue(os.path.exists(state_path))

    def test_text_upload_has_no_dedicated_route(self):
        routes = [route.rule for route in main.app.routes]

        self.assertFalse(any(rule.endswith('/text-upload') for rule in routes))

    def test_content_form_field_wins_when_json_metadata_is_also_present(self):
        with tempfile.TemporaryDirectory() as upload_dir:
            upload = MagicMock()
            upload.raw_filename = 'Image.png'
            upload.file = io.BytesIO(b'file content')

            def save_file(path, overwrite=False):
                del overwrite
                with open(path, 'wb') as destination:
                    destination.write(b'file content')

            upload.save.side_effect = save_file

            request = MagicMock()
            request.json = {'content': 'incorrect fallback'}
            request.files.getall.side_effect = lambda key: [upload] if key == 'content' else []
            request.forms.get.side_effect = lambda key: 'IMG_1491.PNG' if key == 'name' else None

            with (
                patch.object(main, 'UPLOAD_DIR', upload_dir),
                patch.object(main, 'request', request),
                patch.object(main, 'upload_text') as upload_text,
                patch.object(main, 'get_active_files', return_value=[]),
                patch.object(main, 'get_session_size', return_value=0),
                patch.object(main, 'update_session_size_cache'),
                patch.object(main, 'calculate_file_hash', return_value='hash'),
                patch.object(main, 'get_client_ip', return_value='127.0.0.1'),
                patch.object(main, 'log_action'),
                patch.object(main.protection, 'record_access'),
            ):
                result = main.upload_file('session')

            self.assertEqual(result, {'success': True, 'count': 1})
            upload_text.assert_not_called()
            with open(os.path.join(upload_dir, 'session', 'IMG_1491.PNG'), 'rb') as saved_file:
                self.assertEqual(saved_file.read(), b'file content')

    def test_content_json_field_is_saved_as_text(self):
        with tempfile.TemporaryDirectory() as upload_dir:
            request = MagicMock()
            request.json = {'content': 'shortcut text'}
            request.files.getall.return_value = []

            with (
                patch.object(main, 'UPLOAD_DIR', upload_dir),
                patch.object(main, 'request', request),
                patch.object(main, 'get_active_files', return_value=[]),
                patch.object(main, 'get_session_size', return_value=0),
                patch.object(main, 'update_session_size_cache'),
                patch.object(main, 'calculate_file_hash', return_value='hash'),
                patch.object(main, 'get_client_ip', return_value='127.0.0.1'),
                patch.object(main, 'log_action'),
                patch.object(main.protection, 'record_access'),
            ):
                result = main.upload_file('session')

            self.assertEqual(result['success'], True)
            with open(os.path.join(upload_dir, 'session', 'shortcut t.txt'), 'r', encoding='utf-8') as saved_file:
                self.assertEqual(saved_file.read(), 'shortcut text')


if __name__ == '__main__':
    unittest.main()
