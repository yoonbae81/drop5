import io
import os
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

import main


class TestUploadRouting(unittest.TestCase):
    def test_file_upload_wins_when_json_metadata_is_also_present(self):
        with tempfile.TemporaryDirectory() as upload_dir:
            upload = MagicMock()
            upload.raw_filename = 'shortcut.bin'
            upload.file = io.BytesIO(b'file content')

            def save_file(path, overwrite=False):
                del overwrite
                with open(path, 'wb') as destination:
                    destination.write(b'file content')

            upload.save.side_effect = save_file

            request = MagicMock()
            request.json = {'text': 'incorrect fallback'}
            request.files.getall.return_value = [upload]
            request.forms.get.return_value = None

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
            with open(os.path.join(upload_dir, 'session', 'shortcut.bin'), 'rb') as saved_file:
                self.assertEqual(saved_file.read(), b'file content')


if __name__ == '__main__':
    unittest.main()
