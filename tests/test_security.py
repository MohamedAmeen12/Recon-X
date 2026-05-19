import unittest
import json
from app import app

class SecurityTestCase(unittest.TestCase):
    def setUp(self):
        app.config['TESTING'] = True
        self.app = app.test_client()
        # Ensure we have a clean session for each test
        with self.app.session_transaction() as sess:
            sess.clear()

    def test_login_message_parity(self):
        """Verify that both registered and unregistered users get the same error message."""
        # Test with non-existent email
        res1 = self.app.post('/login', json={'email': 'nonexistent_user@gmail.com', 'password': 'somepassword'}, follow_redirects=True)
        # Test with likely existing email but wrong password
        res2 = self.app.post('/login', json={'email': 'admin@reconx.com', 'password': 'wrongpassword'}, follow_redirects=True)
        
        # Check for generic parity message in JSON response
        self.assertIn(b"Invalid email or password", res1.data)
        self.assertIn(b"Invalid email or password", res2.data)

    def test_ssrf_protection(self):
        """Verify that internal IPs are blocked for scanning."""
        payloads = [
            {"domain": "127.0.0.1"},
            {"domain": "localhost"},
            {"domain": "169.254.169.254"}
        ]
        
        # Mock login session with a VALID 24-char hex ObjectId string
        with self.app.session_transaction() as sess:
            sess['user_id'] = '507f1f77bcf86cd799439011' 
            sess['email'] = 'test@example.com'
            sess['role'] = 'admin' # Admin bypasses registered domain check but NOT SSRF
            
        for payload in payloads:
            response = self.app.post('/scan_domain', json=payload)
            self.assertIn(response.status_code, [400, 403])
            data = json.loads(response.data)
            # Depending on if it hits SSRF or Auth check first (SSRF is earlier in the route now)
            self.assertTrue("reject" in data['error'].lower() or "invalid" in data['error'].lower())

    def test_rate_limiting(self):
        """Verify rate limiting on login endpoint."""
        limit_reached = False
        for _ in range(15):
            res = self.app.post('/login', json={'email': 'test@test.com', 'password': 'p'})
            if res.status_code == 429:
                limit_reached = True
                break
        
        self.assertTrue(limit_reached, "Rate limit (429) was not triggered after 15 attempts")

    def test_lab_mode_bypass(self):
        """Verify that lab mode allows CLI bypass and private IP/domain validation skips."""
        import os
        from utils.domain_validator import is_lab_mode_enabled, is_valid_domain, is_domain_allowed
        from utils.ssrf_protection import is_safe_target

        # 1. Enable Lab Mode and test validator/ssrf skips
        os.environ["ENABLE_LAB_SCANNING"] = "true"
        self.assertTrue(is_lab_mode_enabled())
        self.assertTrue(is_valid_domain("172.22.169.150"))
        self.assertTrue(is_valid_domain("localhost"))
        self.assertTrue(is_valid_domain("app.reconx.local"))
        self.assertTrue(is_domain_allowed("172.22.169.150", "172.22.169.0/24"))
        
        safe, reason = is_safe_target("172.22.169.150")
        self.assertTrue(safe)

        # Test auth bypass with X-CLI-Bypass header
        headers = {"X-CLI-Bypass": "reconx_cli_mode", "Content-Type": "application/json"}
        # Send scan request for empty domain (to trigger bad format error rather than 401/403 error)
        res = self.app.post('/scan_domain', json={"domain": ""}, headers=headers)
        # It should return 400 Bad Request (domain required) instead of 401 Unauthorized
        self.assertEqual(res.status_code, 400)

        # 2. Disable Lab Mode and verify it defaults back to secure mode
        os.environ["ENABLE_LAB_SCANNING"] = "false"
        os.environ["DEV_MODE"] = "false"
        self.assertFalse(is_lab_mode_enabled())
        
        # Request without headers should fail with 401
        res2 = self.app.post('/scan_domain', json={"domain": "127.0.0.1"})
        self.assertEqual(res2.status_code, 401)

if __name__ == '__main__':
    unittest.main()
