import unittest
import time
from bottle import Bottle, request, response, abort
import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from middleware import BruteForceProtection, brute_force_plugin

class TestBruteForce(unittest.TestCase):
    def setUp(self):
        # Initialize with small limits for testing
        self.protection = BruteForceProtection(limit=3, window=2, block_duration=2)
        self.app = Bottle()
        self.app.install(brute_force_plugin(self.protection))
        
        @self.app.hook('before_request')
        def check():
            self.protection.check_blocked()
            
        @self.app.route('/<code>')
        def test_route(code):
            return "ok"

    def test_block_after_limit(self):
        # Mock request.remote_addr
        # Bottle request is a thread-local proxy. 
        # In a real test we'd use webtest or similar, but we can simulate it by calling protection directly or mocking request.
        
        from unittest.mock import MagicMock
        import bottle
        
        # We need to mock bottle.request
        bottle.request.environ = {'REMOTE_ADDR': '1.2.3.4'}
        
        # 1st access - Different code
        self.protection.record_access("00001")
        # 2nd access - Different code
        self.protection.record_access("00002")
        
        # 3rd access - DIFFERENT code - Should block
        with self.assertRaises(bottle.HTTPResponse) as cm:
            self.protection.record_access("00003")
        self.assertEqual(cm.exception.status_code, 403)
        self.assertIn("Brute force attempt detected", cm.exception.body)
        
        # Check if actually blocked via check_blocked
        with self.assertRaises(bottle.HTTPResponse) as cm:
            self.protection.check_blocked()
        self.assertEqual(cm.exception.status_code, 403)

    def test_same_code_does_not_block(self):
        import bottle
        bottle.request.environ = {'REMOTE_ADDR': '1.2.3.5'}
        
        # Access 100 times with same code
        for _ in range(10):
            self.protection.record_access("11111")
            
        # Should NOT be blocked
        try:
            self.protection.check_blocked()
        except bottle.HTTPResponse:
            self.fail("Blocked after accessing same code multiple times")

    def test_expiry(self):
        import bottle
        bottle.request.environ = {'REMOTE_ADDR': '1.2.3.6'}
        
        # Set short block duration
        self.protection.block_duration = 1
        
        # Trigger block
        self.protection.record_access("20001")
        self.protection.record_access("20002")
        with self.assertRaises(bottle.HTTPResponse):
            self.protection.record_access("20003")
            
        # Wait for expiry
        time.sleep(1.1)
        
        # Should NOT be blocked anymore
        try:
            self.protection.check_blocked()
        except bottle.HTTPResponse:
            self.fail("Still blocked after expiry")

if __name__ == '__main__':
    unittest.main()
