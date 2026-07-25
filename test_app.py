import unittest
from app import app, db, User


class CyberVaultTestCase(unittest.TestCase):

    def setUp(self):
        """Set up in-memory SQLite database and test environment before each test."""
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

    def test_successful_registration(self):
        """Test user registration with valid details."""
        response = self.app.post('/register', data={
            'fullname': 'Alice Tester',
            'email': 'alice@example.com',
            'password': 'SecurePassword123!',
            'confirm_password': 'SecurePassword123!'
        }, follow_redirects=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Registration successful', response.data)

        with app.app_context():
            user = User.query.filter_by(email='alice@example.com').first()
            self.assertIsNotNone(user)
            self.assertEqual(user.fullname, 'Alice Tester')

    def test_registration_weak_password(self):
        """Test registration fails with weak password."""
        response = self.app.post('/register', data={
            'fullname': 'Bob Weak',
            'email': 'bob@example.com',
            'password': '123',
            'confirm_password': '123'
        }, follow_redirects=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Password must contain minimum 8 characters', response.data)

        with app.app_context():
            user = User.query.filter_by(email='bob@example.com').first()
            self.assertIsNone(user)

    def test_registration_invalid_email(self):
        """Test registration fails with invalid email format."""
        response = self.app.post('/register', data={
            'fullname': 'Charlie Invalid',
            'email': 'not-an-email',
            'password': 'SecurePassword123!',
            'confirm_password': 'SecurePassword123!'
        }, follow_redirects=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Please enter a valid email address', response.data)

    def test_duplicate_registration(self):
        """Test registration fails when email is already registered."""
        # First registration
        self.app.post('/register', data={
            'fullname': 'Alice Tester',
            'email': 'alice@example.com',
            'password': 'SecurePassword123!',
            'confirm_password': 'SecurePassword123!'
        })

        # Duplicate registration
        response = self.app.post('/register', data={
            'fullname': 'Alice Clone',
            'email': 'alice@example.com',
            'password': 'SecurePassword123!',
            'confirm_password': 'SecurePassword123!'
        }, follow_redirects=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Email address is already registered', response.data)

    def test_successful_login_and_logout(self):
        """Test valid user login and logout flow."""
        # Register user
        self.app.post('/register', data={
            'fullname': 'Dave User',
            'email': 'dave@example.com',
            'password': 'SecurePassword123!',
            'confirm_password': 'SecurePassword123!'
        })

        # Login
        response = self.app.post('/login', data={
            'email': 'dave@example.com',
            'password': 'SecurePassword123!'
        }, follow_redirects=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Welcome, Dave User', response.data)

        # Logout
        logout_response = self.app.get('/logout', follow_redirects=True)
        self.assertEqual(logout_response.status_code, 200)
        self.assertIn(b'Logged out successfully', logout_response.data)

    def test_invalid_login(self):
        """Test login fails with incorrect password."""
        response = self.app.post('/login', data={
            'email': 'nonexistent@example.com',
            'password': 'WrongPassword123!'
        }, follow_redirects=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Invalid email or password', response.data)

    def test_protected_routes_unauthenticated(self):
        """Test protected routes redirect unauthenticated users to login."""
        protected_urls = ['/dashboard', '/profile', '/change_password']
        for url in protected_urls:
            response = self.app.get(url, follow_redirects=False)
            self.assertEqual(response.status_code, 302)
            self.assertIn('/login', response.headers['Location'])

    def test_profile_update(self):
        """Test updating user profile."""
        # Register & Login
        self.app.post('/register', data={
            'fullname': 'Eve Original',
            'email': 'eve@example.com',
            'password': 'SecurePassword123!',
            'confirm_password': 'SecurePassword123!'
        })
        self.app.post('/login', data={
            'email': 'eve@example.com',
            'password': 'SecurePassword123!'
        })

        # Update profile
        response = self.app.post('/profile', data={
            'fullname': 'Eve Updated',
            'email': 'eve.new@example.com'
        }, follow_redirects=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Profile updated successfully', response.data)

        with app.app_context():
            user = User.query.filter_by(email='eve.new@example.com').first()
            self.assertIsNotNone(user)
            self.assertEqual(user.fullname, 'Eve Updated')

    def test_change_password(self):
        """Test changing password with old password check and complexity enforcement."""
        # Register & Login
        self.app.post('/register', data={
            'fullname': 'Frank Pass',
            'email': 'frank@example.com',
            'password': 'OldPassword123!',
            'confirm_password': 'OldPassword123!'
        })
        self.app.post('/login', data={
            'email': 'frank@example.com',
            'password': 'OldPassword123!'
        })

        # Change password to weak password (should fail)
        weak_res = self.app.post('/change_password', data={
            'old_password': 'OldPassword123!',
            'new_password': 'weak',
            'confirm_password': 'weak'
        }, follow_redirects=True)
        self.assertIn(b'Password must contain minimum 8 characters', weak_res.data)

        # Change password to valid strong password (should succeed)
        success_res = self.app.post('/change_password', data={
            'old_password': 'OldPassword123!',
            'new_password': 'BrandNewPassword456!',
            'confirm_password': 'BrandNewPassword456!'
        }, follow_redirects=True)

        self.assertEqual(success_res.status_code, 200)
        self.assertIn(b'Password updated successfully', success_res.data)

    def test_custom_404(self):
        """Test non-existent route returns 404 page."""
        response = self.app.get('/this-route-does-not-exist')
        self.assertEqual(response.status_code, 404)
        self.assertIn(b'Page Not Found', response.data)


if __name__ == '__main__':
    unittest.main()
