# 🛡️ CyberVault - Secure Web Application

**CyberVault** is a security-focused web application built with **Flask**, **SQLite**, **Bcrypt**, and **Bootstrap 5.3**. It demonstrates modern web development best practices, secure session management, strong password policy enforcement, and defense against common web vulnerabilities (SQL Injection, CSRF, and XSS).

---

## ✨ Features

- 🔐 **Password Hashing (Bcrypt)**: User credentials are encrypted with salt-augmented Bcrypt before database storage.
- 🛡️ **SQL Injection Protection**: Parametrized queries managed via **SQLAlchemy 2.0 ORM**.
- 📏 **Strong Password Policy**: Password complexity validation (min 8 chars, uppercase, lowercase, numbers, and special characters) enforced on both Registration and Password Change.
- 📊 **Real-time Password Strength Meter**: Interactive visual feedback bar and live requirements checklist on registration.
- 🔑 **User Authentication & Route Guards**: Session-based login/logout management powered by **Flask-Login** with `@login_required` protected routes.
- 👤 **Profile & Password Management**: Users can securely edit their account details and update passwords.
- 🌐 **HTTP Security Headers**: Active response headers (`X-Frame-Options`, `X-Content-Type-Options`, `X-XSS-Protection`).
- 🎨 **Modern Responsive UI**: Dark glassmorphic design theme built with Bootstrap 5.3.3 and FontAwesome icons.
- 🧪 **Automated Test Suite**: 100% passing `unittest` test suite covering authentication, validation, authorization, and error handlers.

---

## 🛠️ Technology Stack

- **Backend**: Python 3.x, Flask 3.1
- **Database**: SQLite, Flask-SQLAlchemy 3.1
- **Security & Encryption**: Flask-Bcrypt, Flask-Login
- **Frontend**: HTML5, Vanilla CSS3, JavaScript (ES6), Bootstrap 5.3.3, FontAwesome 6.5.2
- **Testing**: Python `unittest` framework

---

## 🚀 How an Evaluator Can Run & Test This Project

### 1. Clone the Repository
```bash
git clone https://github.com/yuthika-codes/CyberVault-Secure-Web-App.git
cd CyberVault-Secure-Web-App
```

### 2. Create & Activate a Virtual Environment
- **On Windows (PowerShell)**:
  ```powershell
  python -m venv venv
  .\venv\Scripts\activate
  ```
- **On macOS / Linux**:
  ```bash
  python3 -m venv venv
  source venv/bin/activate
  ```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Run the Application
```bash
python app.py
```
Open your browser and navigate to **`http://127.0.0.1:5000`**.

---

## 🧪 Running Automated Unit Tests

To run the automated unit test suite:
```bash
python -m unittest test_app.py
```

All 11 unit tests will run in an isolated in-memory database and output `OK`.

---

## 📂 Project Directory Structure

```text
Secure-Web-App/
├── app.py                  # Main Flask Application & Security Routes
├── requirements.txt        # Python Dependencies
├── test_app.py             # Automated Unit Test Suite
├── .gitignore              # Git Ignore Rules
├── README.md               # Project Documentation
├── static/
│   └── css/
│       └── style.css       # Custom Glassmorphic CSS System
└── templates/
    ├── base.html           # Master Jinja2 Base Layout & Navbar
    ├── home.html           # Landing / Hero Page
    ├── login.html          # Login Form Page
    ├── register.html       # Register Form & Password Strength Meter
    ├── dashboard.html      # Protected User Security Dashboard
    ├── profile.html        # Account Edit Page
    ├── change_password.html # Change Password Page
    ├── 404.html            # Custom Page Not Found Template
    └── 500.html            # Custom Server Error Template
```

---

## 📜 License
This project is licensed under the MIT License - feel free to use and extend for educational purposes!
