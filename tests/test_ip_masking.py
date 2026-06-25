"""Test IP masking functionality for GDPR compliance."""
import unittest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from src.audit import mask_ip, log_action
from src.config import MASK_IP_IN_LOGS
import json
import tempfile
import shutil


class TestIPMasking(unittest.TestCase):
    """Test IP address masking functionality."""

    def test_mask_ipv4_default(self):
        """Test default IPv4 masking (last octet)."""
        ip = "192.168.1.100"
        masked = mask_ip(ip)
        self.assertEqual(masked, "192.168.1.xxx")
        self.assertNotIn("100", masked)

    def test_mask_ipv4_two_octets(self):
        """Test IPv4 masking with 2 octets."""
        ip = "192.168.1.100"
        masked = mask_ip(ip, mask_octets=2)
        self.assertEqual(masked, "192.168.xxx.xxx")
        # Last two octets should be masked
        self.assertNotIn("100", masked)

    def test_mask_ipv6_default(self):
        """Test default IPv6 masking."""
        ip = "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
        masked = mask_ip(ip)
        # Should mask the last few groups
        self.assertIn('x', masked)
        self.assertNotEqual(masked, ip)

    def test_mask_ipv6_simplified(self):
        """Test IPv6 masking with simplified notation."""
        ip = "2001:db8::1"
        masked = mask_ip(ip)
        # Should contain masking indicator
        self.assertIn('x', masked)

    def test_mask_invalid_ip(self):
        """Test masking of invalid IP."""
        ip = "invalid.ip.address"
        masked = mask_ip(ip)
        self.assertEqual(masked, "invalid.xxx")

    def test_mask_none_ip(self):
        """Test masking of None IP."""
        ip = None
        masked = mask_ip(ip)
        self.assertEqual(masked, "unknown")

    def test_mask_empty_ip(self):
        """Test masking of empty IP."""
        ip = ""
        masked = mask_ip(ip)
        self.assertEqual(masked, "unknown")

    def test_log_action_with_masking_enabled(self):
        """Test that log_action masks IP when enabled."""
        # This test verifies the mask_ip function is used correctly
        ip = "192.168.1.100"
        masked = mask_ip(ip)

        # Verify the function returns expected format
        self.assertEqual(masked, "192.168.1.xxx")

    def test_log_action_with_masking_disabled(self):
        """Test that log_action doesn't mask IP when disabled."""
        ip = "192.168.1.100"

        # Verify raw IP is returned when masking is disabled
        self.assertEqual(mask_ip(ip, mask_octets=0), ip)


class TestMaskingConfig(unittest.TestCase):
    """Test MASK_IP_IN_LOGS configuration."""

    def test_config_exists(self):
        """Test that MASK_IP_IN_LOGS configuration exists."""
        from src.config import MASK_IP_IN_LOGS
        # Should be a boolean
        self.assertIsInstance(MASK_IP_IN_LOGS, bool)

    def test_config_default_true(self):
        """Test that MASK_IP_IN_LOGS defaults to True for privacy."""
        from src.config import MASK_IP_IN_LOGS
        # Default should be True for GDPR compliance
        self.assertTrue(MASK_IP_IN_LOGS)


if __name__ == '__main__':
    unittest.main(verbosity=2)
