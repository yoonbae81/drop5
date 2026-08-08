import unittest

from src.middleware import SecurityMiddleware


class TestSecurityDelegation(unittest.TestCase):
    def test_security_middleware_does_not_apply_local_brute_force_rules(self):
        protection = SecurityMiddleware()

        protection.record_access(code='00001')
        protection.record_access(code='00002')
        protection.record_access(code='00003')

        protection.check_blocked()


if __name__ == '__main__':
    unittest.main()
