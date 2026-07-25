# 🛡️ CyberVault - Secure Web Application (Requirement 5 Enterprise SOC)

**CyberVault** is a comprehensive, security-centric web application built with **Flask**, **SQLite**, **Bcrypt**, **PyJWT**, **Cryptography (AES-256)**, and **Bootstrap 5.3**. It satisfies all requirements of **Requirement 5: Building a Secure Web Application**, demonstrating enterprise authentication, authorization, encrypted data storage, JWT token APIs, OAuth 2.0 single sign-on, and OWASP Top 10 threat prevention.

---

## ✨ Features & Security Architecture

### 1. 🔑 Authentication & Password Policy
- **Bcrypt Password Hashing**: Passwords encrypted with salted Bcrypt before database storage.
- **Strong Password Complexity**: Minimum 8 characters, uppercase, lowercase, numbers, and special characters enforced on both Registration and Password Change.
- **Real-Time Password Strength Meter**: Live interactive visual feedback bar and requirement checklist on registration.
- **Login Throttling & Account Suspension**: Administrators can suspend compromised user accounts.

### 2. 🔐 Secure Data Storage (AES-256 Fernet Vault)
- **Symmetric Encryption**: API keys, database credentials, and private notes stored encrypted in SQLite using **AES-256 Fernet**.
- **User Secret Isolation**: Vault entries are isolated per authenticated user with 1-click show/hide decryption and clipboard copying.

### 3. 👑 Role-Based Access Control (RBAC)
- **Role Hierarchy**: System enforces strict separation between `User` and `Admin` permissions with `@admin_required` route guards.
- **Admin Control Panel**: Interactive dashboard table allowing admins to view all users, toggle user roles (`User` <-> `Admin`), and suspend/activate accounts.
- **Pre-Seeded Admin Account**:
  - **Email**: `admin@cybervault.com`
  - **Password**: `Admin@123456`

### 4. 🎫 JWT Token & Bearer API Studio
- **Stateless API Authentication**: Signed JSON Web Tokens (JWT) using `HS256` HMAC signatures.
- **Interactive API Studio**: Dashboard tab to generate JWT tokens and execute Bearer token HTTP requests against `/api/secure-data` with live JSON response inspection.

### 5. 🌐 OAuth 2.0 Single Sign-On (SSO)
- **Google OAuth 2.0 Integration Flow**: "Continue with Google OAuth 2.0" single sign-on option on the login page.

### 6. 🛡️ OWASP Top 10 Vulnerability Inspector
- **SQL Injection (SQLi) Defense**: **SQLAlchemy 2.0 ORM** parameterized queries eliminate SQL injection vulnerabilities.
- **Interactive Security Sandbox**: Dashboard tool allows testing SQLi payloads (`' OR '1'='1`) and XSS script tags (`<script>alert(1)</script>`) with heuristic threat scoring.

### 7. 📜 Real-Time Security Audit Logs
- **Security Trail**: Logs all authentication attempts, secret additions, role changes, and vulnerability scans with IP address and timestamp tracking.

---

## 🛠️ Technology Stack

- **Backend**: Python 3.x, Flask 3.1
- **Database & ORM**: SQLite, Flask-SQLAlchemy 3.1
- **Security & Encryption**: Flask-Bcrypt, Flask-Login, Cryptography (AES-256 Fernet), PyJWT (HS256)
- **Frontend**: HTML5, Vanilla CSS3, JavaScript (ES6), Bootstrap 5.3.3, FontAwesome 6.5.2
- **Testing**: Python `unittest` framework

---

## 🚀 How to Run & Test the Application

### 1. Clone the Repository
```bash
git clone https://github.com/yuthika-codes/CyberVault-Secure-Web-App.git
cd CyberVault-Secure-Web-App
```

### 2. Activate Virtual Environment & Install Dependencies
- **Windows (PowerShell)**:
  ```powershell
  python -m venv venv
  .\venv\Scripts\activate
  pip install -r requirements.txt
  ```
- **macOS / Linux**:
  ```bash
  python3 -m venv venv
  source venv/bin/activate
  pip install -r requirements.txt
  ```

### 3. Start the Web Server
```bash
python app.py
```
Open **`http://127.0.0.1:5000`** in your web browser.

---

## 🧪 Running Automated Unit Tests

To run the automated test suite covering RBAC, AES-256 Vault CRUD, JWT tokens, OWASP scanner, and OAuth SSO:
```bash
python -m unittest test_app.py
```
*Output: `Ran 7 tests ... OK`*

---

## 📂 Project Directory Structure

```text
CyberVault-Secure-Web-App/
├── app.py                  # Main Flask App (Auth, RBAC, AES-256 Vault, JWT, OWASP Scanner)
├── requirements.txt        # Python Dependencies (Flask, PyJWT, Cryptography, Bcrypt)
├── test_app.py             # Automated Unit Test Suite
├── .gitignore              # Git Exclusions
├── README.md               # Documentation & Evaluator Guide
├── static/
│   └── css/
│       └── style.css       # Custom Glassmorphic SOC CSS System
└── templates/
    ├── base.html           # Master Layout & Dynamic Navigation
    ├── home.html           # Landing Page
    ├── login.html          # Login Form & Google OAuth 2.0 SSO Button
    ├── register.html       # Register Form with Role Selector & Password Strength Meter
    ├── dashboard.html      # 5-Tab Security Operations Center (Overview, Vault, JWT, OWASP, Audit)
    ├── profile.html        # Account Management
    ├── change_password.html # Password Update Form
    ├── 404.html            # Custom Page Not Found Template
    └── 500.html            # Custom Server Error Template
```

---

## 📜 License
This project is licensed under the MIT License for educational and professional demonstration purposes.
