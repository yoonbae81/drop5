import unittest
import os
import json
import sys

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from i18n import get_translations, get_available_languages


class TestI18n(unittest.TestCase):
    """Test cases for i18n translations"""

    def setUp(self):
        """Set up test fixtures."""
        self.i18n_dir = os.path.join(os.path.dirname(__file__), '..', 'src', 'i18n', 'locales')
        self.reference_file = os.path.join(self.i18n_dir, 'en.json')

    def test_all_translations_have_same_keys(self):
        """Test that all i18n JSON files have the same keys as en.json"""
        # Load reference keys from en.json
        with open(self.reference_file, 'r', encoding='utf-8') as f:
            reference_data = json.load(f)
            reference_keys = set(reference_data.keys())

        # Get all JSON files in i18n directory
        json_files = [f for f in os.listdir(self.i18n_dir) if f.endswith('.json') and f != 'en.json']

        missing_keys_report = []

        for json_file in json_files:
            file_path = os.path.join(self.i18n_dir, json_file)
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                current_keys = set(data.keys())

                # Check for missing keys
                missing = reference_keys - current_keys
                if missing:
                    missing_keys_report.append(f"{json_file}: Missing keys {sorted(missing)}")

                # Check for extra keys (optional, can be useful to catch typos)
                extra = current_keys - reference_keys
                if extra:
                    missing_keys_report.append(f"{json_file}: Extra keys {sorted(extra)}")

        # If any files have missing or extra keys, fail the test with a detailed report
        if missing_keys_report:
            error_message = "\n".join(missing_keys_report)
            self.fail(f"Translation key mismatch found:\n{error_message}")

    def test_reference_file_exists(self):
        """Test that the reference file (en.json) exists"""
        self.assertTrue(os.path.exists(self.reference_file), "Reference file en.json does not exist")

    def test_reference_file_is_valid_json(self):
        """Test that the reference file is valid JSON"""
        with open(self.reference_file, 'r', encoding='utf-8') as f:
            try:
                json.load(f)
            except json.JSONDecodeError as e:
                self.fail(f"Reference file en.json is not valid JSON: {e}")

    def test_all_json_files_are_valid(self):
        """Test that all JSON files in i18n directory are valid"""
        json_files = [f for f in os.listdir(self.i18n_dir) if f.endswith('.json')]

        for json_file in json_files:
            file_path = os.path.join(self.i18n_dir, json_file)
            with open(file_path, 'r', encoding='utf-8') as f:
                try:
                    data = json.load(f)
                    # Ensure it's a dictionary
                    self.assertIsInstance(data, dict, f"{json_file} does not contain a JSON object")
                except json.JSONDecodeError as e:
                    self.fail(f"{json_file} is not valid JSON: {e}")

    def test_get_available_languages(self):
        """Test that get_available_languages returns expected languages"""
        languages = get_available_languages()
        self.assertIsInstance(languages, list)
        self.assertGreater(len(languages), 0)
        self.assertIn('en', languages)
        self.assertIn('ko', languages)

    def test_get_translations(self):
        """Test that get_translations works correctly"""
        # Test loading a known language
        translations = get_translations('en')
        self.assertIsInstance(translations, dict)
        self.assertIn('upload_text', translations)
        self.assertIn('upload_text', translations)

        # Test loading a non-existent language (should return English as fallback)
        translations = get_translations('nonexistent')
        self.assertIsInstance(translations, dict)
        self.assertIn('upload_text', translations)  # Should fallback to English

    def test_get_translations_fallback(self):
        """Test that get_translations falls back to English for missing languages"""
        # Test with a non-existent language
        translations = get_translations('nonexistent')
        # Should return English translations as fallback
        self.assertIsInstance(translations, dict)
        self.assertIn('upload_text', translations)


if __name__ == '__main__':
    unittest.main()
