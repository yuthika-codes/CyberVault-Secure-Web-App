# 🛡️ CyberVault - Secure Web Application & SOC Security Suite

[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy?repo=https://github.com/yuthika-codes/CyberVault-Secure-Web-App)

**CyberVault** is a comprehensive, enterprise-grade security web application built with **Flask**, **SQLite**, **Bcrypt**, **PyJWT**, **Cryptography (AES-256)**, **OpenCV**, **Pillow**, and **Bootstrap 5.3**. It delivers real-time threat intelligence and vulnerability analysis across three core scanners: **Password Security & Leak Scanner**, **Phishing & URL Safety Inspector**, and **QR Code Safety Scanner**.


---

## ✨ Features & Security Architecture

### 1. 🔑 Authentication & Password Policy
- **Bcrypt Password Hashing**: User passwords are securely salted and hashed using Bcrypt before database storage.
- **Strict Password Complexity**: Enforces length >= 8, uppercase, lowercase, numbers, and special characters (`!@#$%^&*`).
- **Interactive Password Visibility Toggle**: Eye icons on all forms allow toggling password visibility with debounced event handlers.
- **Account Suspension & RBAC**: Admin-controlled user roles (`user` vs `admin`) and account suspension capabilities.

### 2. 🛡️ 3-Tab Security Operations Center (SOC) Scanners

#### 🔑 Tab 1: Password Security & Leak Scanner
- **Entropy & Complexity Analysis**: Evaluates password length, character diversity, and structure.
- **Crack Time Estimation**: Calculates estimated time required for brute-force cracking.
- **Known Leak Pattern Detection**: Checks candidate passwords against common wordlists and compromised breaches (`123456`, `password123`, etc.).

#### 🌐 Tab 2: Phishing & URL Safety Inspector
- **Brand Mimicking & Typosquatting Detection**: Identifies fake domain names imitating popular services (e.g. `paypal-security-login.xyz`).
- **Raw IP Host Inspection**: Flags non-domain IP address hosts (`http://192.168.1.50/login`).
- **High-Risk TLD & Protocol Alerts**: Alerts on unencrypted `http://` protocols and high-risk top-level domains (`.xyz`, `.top`, `.zip`).

#### 📱 Tab 3: QR Code Safety Scanner
- **Dual Decoding Engine**: Accepts image file uploads (`.png`, `.jpg`, `.jpeg`, `.webp`) decoded using **OpenCV (`cv2.QRCodeDetector`)** & **Pillow**, or accepts direct URL / text input.
- **Malicious Payload & Executable Detection**: Detects direct executable downloads (`.exe`, `.apk`, `.vbs`, `.bat`) embedded within QR codes.
- **Categorized Risk Status**: Reports explicit status output (**✅ Safe**, **⚠️ Suspicious**, **🚨 Potentially Malicious**) with actionable security recommendations.

### 3. 🔐 Secure Data Storage (AES-256 Fernet Vault)
- **Symmetric Encryption**: User credentials, API tokens, and private notes stored encrypted in SQLite using **AES-256 Fernet**.
- **User Isolation**: Vault entries are isolated per authenticated user with one-click show/hide decryption.

### 4. 🎫 JWT Token & Bearer API Studio
- **Stateless API Authentication**: Generates signed JSON Web Tokens (JWT) using `HS256` HMAC signatures.
- **Interactive API Studio**: Evaluates Bearer token HTTP requests against `/api/secure-data` with live JSON response inspection.

### 5. 🌐 OAuth 2.0 Single Sign-On (SSO)
- **Google OAuth 2.0 Integration Flow**: Includes "Continue with Google OAuth 2.0" single sign-on flow.

### 6. 📜 Real-Time Security Audit Logs
- **Comprehensive Audit Trail**: Tracks authentication events, role changes, secret additions, and security scans with IP address and timestamp recording.

---

## 🛠️ Technology Stack

- **Backend**: Python 3.x, Flask 3.1
- **Database & ORM**: SQLite, Flask-SQLAlchemy 3.1
- **Security & Encryption**: Flask-Bcrypt, Flask-Login, Cryptography (AES-256 Fernet), PyJWT (HS256)
- **Image Processing & Computer Vision**: OpenCV (`opencv-python-headless`), Pillow, QRCode
- **WSGI Production Server**: Gunicorn
- **Frontend**: HTML5, Vanilla CSS3, JavaScript (ES6), Bootstrap 5.3.3, FontAwesome 6.5.2
- **Testing**: Python `unittest` framework

---

## 🚀 How to Run Locally

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

To run the automated unit test suite covering RBAC, AES-256 Vault, JWT Tokens, URL Safety, and QR Code Scanner:
```bash
python -m unittest test_app.py
```
*Output: `Ran 9 tests ... OK`*

---

## 🌐 Deploying to Production (Render / Railway / Heroku)

### Deployment on Render.com (Recommended - Free Tier):
1. Create a new **Web Service** on [Render.com](https://render.com) and connect your GitHub repository `CyberVault-Secure-Web-App`.
2. Configure settings:
   - **Environment**: `Python 3`
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `gunicorn app:app`
3. Click **Create Web Service**. Your application will be live with full SSL/HTTPS support!

---

## 📂 Project Directory Structure

```text
CyberVault-Secure-Web-App/
├── app.py                  # Main Flask App (Auth, Scanners, AES-256 Vault, JWT, QR Scanner API)
├── requirements.txt        # Python Dependencies (Flask, PyJWT, Cryptography, OpenCV, Pillow, Gunicorn)
├── Procfile                # Production WSGI deployment config (gunicorn app:app)
├── test_app.py             # Automated Unit Test Suite (9 Tests)
├── .gitignore              # Git Exclusions
├── README.md               # Documentation & Evaluator Guide
├── static/
│   └── css/
│       └── style.css       # Glassmorphic SOC CSS System
└── templates/
    ├── base.html           # Master Layout & Universal Password Visibility Toggle
    ├── home.html           # Landing Page
    ├── login.html          # Login Form & Google OAuth 2.0 SSO Button
    ├── register.html       # Register Form with Role Selector & Password Strength Meter
    ├── dashboard.html      # 3-Tab Security Operations Center (Password, URL, and QR Code Scanners)
    ├── profile.html        # Account Management
    ├── change_password.html # Password Update Form
    ├── 404.html            # Custom 404 Template
    └── 500.html            # Custom 500 Template
```

---

## 📜 License
This project is licensed under the MIT License for educational and professional demonstration purposes.
