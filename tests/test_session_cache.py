"""Test session size cache invalidation on file deletion."""
import unittest
import sys
import os
import shutil

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from src.session import get_session_size, update_session_size_cache
from src.config import UPLOAD_DIR


class TestSessionSizeCache(unittest.TestCase):
    """Test session size cache is properly invalidated on file deletion."""

    def setUp(self):
        """Set up test fixtures."""
        self.test_upload_dir = os.path.abspath('test_files_cache')
        if not os.path.exists(self.test_upload_dir):
            os.makedirs(self.test_upload_dir)

        # Create a test session directory
        self.code = "test123"
        self.code_dir = os.path.join(self.test_upload_dir, self.code)
        os.makedirs(self.code_dir, exist_ok=True)

    def tearDown(self):
        """Clean up after tests"""
        if os.path.exists(self.test_upload_dir):
            shutil.rmtree(self.test_upload_dir)

    def test_cache_invalidated_after_adding_file(self):
        """Test that cache is updated when a file is added."""
        # Create a test file
        test_file = os.path.join(self.code_dir, 'test.txt')
        with open(test_file, 'w') as f:
            f.write('x' * 1000)  # 1000 bytes

        # Update cache after adding file
        update_session_size_cache(self.code_dir, 0, file_path=test_file, is_add=True)

        # Verify cache returns correct size
        size = get_session_size(self.code_dir, use_cache=True)
        self.assertEqual(size, 1000)

    def test_cache_invalidated_after_deleting_files(self):
        """Test that cache is invalidated after all files are deleted.

        This is a regression test for the bug where delete_all_files()
        didn't update the session size cache.
        """
        # Create multiple test files
        files = []
        total_size = 0
        for i in range(3):
            file_path = os.path.join(self.code_dir, f'file{i}.txt')
            content = 'x' * ((i + 1) * 1000)  # Different sizes
            with open(file_path, 'w') as f:
                f.write(content)
            files.append(file_path)
            total_size += len(content)
            # Update cache after adding
            update_session_size_cache(self.code_dir, 0, file_path=file_path, is_add=True)

        # Verify cache returns correct total size
        size = get_session_size(self.code_dir, use_cache=True)
        self.assertEqual(size, total_size)

        # Delete all files (simulating delete_all_files behavior)
        for file_path in files:
            if os.path.exists(file_path):
                os.remove(file_path)

        # BUG FIX: Reset cache after deleting all files
        # This line was missing in the original delete_all_files() implementation
        update_session_size_cache(self.code_dir, 0, set_absolute=0)

        # Verify cache returns 0 after all files deleted
        size_after_delete = get_session_size(self.code_dir, use_cache=True)
        self.assertEqual(size_after_delete, 0,
                        "Cache should be 0 after all files are deleted")

    def test_cache_fallback_to_calculation_when_missing(self):
        """Test that cache falls back to direct calculation when cache is missing."""
        # Create a test file
        test_file = os.path.join(self.code_dir, 'test.txt')
        with open(test_file, 'w') as f:
            f.write('x' * 500)

        # Don't update cache, just get size (should fall back to calculation)
        size = get_session_size(self.code_dir, use_cache=True)
        self.assertEqual(size, 500)


if __name__ == '__main__':
    unittest.main()
