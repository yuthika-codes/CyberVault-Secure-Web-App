import unittest
import json
from app import app, db, User, SecretVault, AuditLog


class CyberVaultRequirement5TestCase(unittest.TestCase):

    def setUp(self):
        """Set up in-memory database and testing environment."""
        app.config['TESTING'] = True
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        app.config['WTF_CSRF_ENABLED'] = False
        self.app = app.test_client()

        with app.app_context():
            db.create_all()

    def tearDown(self):
        """Clean up database after each test."""
        with app.app_context():
            db.session.remove()
            db.drop_all()

    def test_home_page(self):
        """Test home route loads successfully."""
        response = self.app.get('/')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'CyberVault', response.data)

    def test_successful_registration_and_rbac_role(self):
        """Test user registration with role selection."""
        response = self.app.post('/register', data={
            'fullname': 'Alice Admin',
            'email': 'alice.admin@example.com',
            'password': 'SecurePassword123!',
            'confirm_password': 'SecurePassword123!',
            'role': 'admin'
        }, follow_redirects=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Registration successful', response.data)

        with app.app_context():
            user = User.query.filter_by(email='alice.admin@example.com').first()
            self.assertIsNotNone(user)
            self.assertEqual(user.role, 'admin')

    def test_aes256_encrypted_vault_crud(self):
        """Test storing, decrypting, and deleting secrets in AES-256 Vault."""
        # Register and Login
        self.app.post('/register', data={
            'fullname': 'Vault Owner',
            'email': 'vault@example.com',
            'password': 'SecurePassword123!',
            'confirm_password': 'SecurePassword123!'
        })
        self.app.post('/login', data={
            'email': 'vault@example.com',
            'password': 'SecurePassword123!'
        })

        # Add secret to Vault
        add_res = self.app.post('/vault/add', data={
            'title': 'Stripe Production API Key',
            'category': 'API Key',
            'raw_secret': 'dummy_api_key_sample_vault_secret_12345'
        }, follow_redirects=True)

        self.assertEqual(add_res.status_code, 200)
        self.assertIn(b'encrypted with AES-256', add_res.data)

        with app.app_context():
            user = User.query.filter_by(email='vault@example.com').first()
            secret = SecretVault.query.filter_by(user_id=user.id).first()
            self.assertIsNotNone(secret)
            self.assertEqual(secret.title, 'Stripe Production API Key')
            # Verify database stores encrypted text, NOT raw text
            self.assertNotEqual(secret.encrypted_secret, 'dummy_api_key_sample_vault_secret_12345')
            # Verify decryption method returns original secret
            self.assertEqual(secret.get_decrypted_secret(), 'dummy_api_key_sample_vault_secret_12345')

            secret_id = secret.id

        # Delete secret
        del_res = self.app.post(f'/vault/delete/{secret_id}', follow_redirects=True)
        self.assertEqual(del_res.status_code, 200)
        self.assertIn(b'Secret deleted from vault', del_res.data)

    def test_jwt_token_generation_and_api_bearer_auth(self):
        """Test JWT token generation and Bearer authorization on /api/secure-data."""
        # Register user
        self.app.post('/register', data={
            'fullname': 'API Tester',
            'email': 'api@example.com',
            'password': 'SecurePassword123!',
            'confirm_password': 'SecurePassword123!'
        })

        # Obtain JWT Token
        token_res = self.app.post('/api/auth/token', data=json.dumps({
            'email': 'api@example.com',
            'password': 'SecurePassword123!'
        }), content_type='application/json')

        self.assertEqual(token_res.status_code, 200)
        data = json.loads(token_res.data)
        self.assertEqual(data['status'], 'success')
        jwt_token = data['token']

        # Access protected API without token (should fail 401)
        unauth_res = self.app.get('/api/secure-data')
        self.assertEqual(unauth_res.status_code, 401)

        # Access protected API with valid Bearer JWT token (should succeed 200)
        auth_res = self.app.get('/api/secure-data', headers={
            'Authorization': f'Bearer {jwt_token}'
        })
        self.assertEqual(auth_res.status_code, 200)
        auth_data = json.loads(auth_res.data)
        self.assertEqual(auth_data['status'], 'authorized')
        self.assertEqual(auth_data['authenticated_as']['email'], 'api@example.com')

    def test_phishing_and_url_safety_scanner(self):
        """Test Phishing & URL Safety Scanner API detecting suspicious and safe URLs."""
        # Test Phishing URL
        phishing_res = self.app.post('/api/url-scan', json={
            'url': 'http://paypal-security-verify-account.xyz/login.php'
        })
        self.assertEqual(phishing_res.status_code, 200)
        phishing_data = json.loads(phishing_res.data)
        self.assertIn(phishing_data['status'], ['SUSPICIOUS', 'PHISHING_ALERT'])
        self.assertLess(phishing_data['threat_score'], 80)

        # Test Safe URL
        safe_res = self.app.post('/api/url-scan', json={
            'url': 'https://github.com/login'
        })
        self.assertEqual(safe_res.status_code, 200)
        safe_data = json.loads(safe_res.data)
        self.assertEqual(safe_data['status'], 'SAFE')
        self.assertEqual(safe_data['threat_score'], 100)

    def test_oauth_google_sso_flow(self):
        """Test simulated Google OAuth 2.0 SSO sign-in."""
        response = self.app.get('/auth/oauth/google', follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Authenticated via Google OAuth 2.0 SSO', response.data)

    def test_admin_rbac_authorization_guards(self):
        """Test that regular users cannot access Admin management functions."""
        # Register standard user
        self.app.post('/register', data={
            'fullname': 'Standard User',
            'email': 'user@example.com',
            'password': 'SecurePassword123!',
            'confirm_password': 'SecurePassword123!',
            'role': 'user'
        })
        self.app.post('/login', data={
            'email': 'user@example.com',
            'password': 'SecurePassword123!'
        })

        # Attempt to trigger admin user role toggle
        res = self.app.post('/admin/user/1/toggle-role', follow_redirects=True)
        self.assertIn(b'Admin privileges required', res.data)


if __name__ == '__main__':
    unittest.main()
