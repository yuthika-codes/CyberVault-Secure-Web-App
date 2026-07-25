import os
import re
from datetime import datetime, timedelta
from urllib.parse import urlparse
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    login_required,
    logout_user,
    current_user
)
from cryptography.fernet import Fernet
import jwt

# ==========================
# Create Flask App & Configuration
# ==========================

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "cybervault_enterprise_secret_2026")
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# ==========================
# AES-256 Symmetric Encryption Key Setup
# ==========================

FERNET_KEY_ENV = os.environ.get("FERNET_KEY")
if FERNET_KEY_ENV:
    cipher_suite = Fernet(FERNET_KEY_ENV.encode())
else:
    # Generate valid base64 Fernet key dynamically
    cipher_suite = Fernet(Fernet.generate_key())

# ==========================
# Initialize Extensions
# ==========================

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# ==========================
# Login Manager Setup
# ==========================

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
login_manager.login_message_category = "warning"
login_manager.login_message = "Please log in to access this page."


# ==========================
# Database Models
# ==========================

class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    fullname = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default="user", nullable=False)  # 'user' or 'admin'
    is_suspended = db.Column(db.Boolean, default=False, nullable=False)
    last_login = db.Column(db.String(100), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    secrets = db.relationship("SecretVault", backref="owner", lazy=True, cascade="all, delete-orphan")
    audit_logs = db.relationship("AuditLog", backref="user", lazy=True)


class SecretVault(db.Model):
    __tablename__ = "secret_vault"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    title = db.Column(db.String(100), nullable=False)
    category = db.Column(db.String(50), default="API Key", nullable=False)
    encrypted_secret = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_secret(self, raw_secret):
        """Encrypt secret data using AES-256 Fernet."""
        self.encrypted_secret = cipher_suite.encrypt(raw_secret.encode("utf-8")).decode("utf-8")

    def get_decrypted_secret(self):
        """Decrypt secret data for authorized owner."""
        try:
            return cipher_suite.decrypt(self.encrypted_secret.encode("utf-8")).decode("utf-8")
        except Exception:
            return "[Decryption Error]"


class AuditLog(db.Model):
    __tablename__ = "audit_logs"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    event = db.Column(db.String(255), nullable=False)
    ip_address = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(20), default="SUCCESS", nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


# ==========================
# Load User Callback
# ==========================

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


# ==========================
# Helper & Security Functions
# ==========================

def log_security_event(event, status="SUCCESS", user_id=None):
    """Log security events to the AuditLog database table."""
    uid = user_id or (current_user.id if current_user and current_user.is_authenticated else None)
    ip = request.remote_addr or "127.0.0.1"
    log_entry = AuditLog(user_id=uid, event=event, ip_address=ip, status=status)
    db.session.add(log_entry)
    db.session.commit()


def admin_required(f):
    """Decorator to enforce Admin Role-Based Access Control (RBAC)."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != "admin":
            log_security_event("Unauthorized Admin Access Attempt", status="DENIED")
            flash("Access denied! Admin privileges required.", "danger")
            return redirect(url_for("dashboard"))
        return f(*args, **kwargs)
    return decorated_function


def is_valid_email(email):
    pattern = r"^[\w\.-]+@[\w\.-]+\.\w+$"
    return bool(re.match(pattern, email))


def validate_password(password):
    if len(password) < 8:
        return False, "Password must contain minimum 8 characters"
    if not re.search(r"[A-Z]", password):
        return False, "Password needs an uppercase letter"
    if not re.search(r"[a-z]", password):
        return False, "Password needs a lowercase letter"
    if not re.search(r"[0-9]", password):
        return False, "Password needs a number"
    if not re.search(r"[!@#$%^&*]", password):
        return False, "Password needs a special character (!@#$%^&*)"
    return True, ""


def generate_jwt(user):
    """Generate signed JWT Token for API authentication."""
    payload = {
        "sub": str(user.id),
        "name": user.fullname,
        "email": user.email,
        "role": user.role,
        "iat": datetime.utcnow(),
        "exp": datetime.utcnow() + timedelta(hours=2)
    }
    return jwt.encode(payload, app.config["SECRET_KEY"], algorithm="HS256")


# ==========================
# Security Headers Middleware
# ==========================

@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    return response


# ==========================
# Error Handlers
# ==========================

@app.errorhandler(404)
def page_not_found(e):
    return render_template("404.html"), 404


@app.errorhandler(500)
def internal_server_error(e):
    return render_template("500.html"), 500


# ==========================
# Application Routes
# ==========================

@app.route("/")
def home():
    return render_template("home.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        fullname = request.form.get("fullname", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")
        role = request.form.get("role", "user")

        if role not in ["user", "admin"]:
            role = "user"

        if not fullname:
            flash("Full Name is required", "danger")
            return redirect(url_for("register"))

        if not is_valid_email(email):
            flash("Please enter a valid email address", "danger")
            return redirect(url_for("register"))

        is_valid, err_msg = validate_password(password)
        if not is_valid:
            flash(err_msg, "danger")
            return redirect(url_for("register"))

        if password != confirm_password:
            flash("Passwords do not match", "danger")
            return redirect(url_for("register"))

        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash("Email address is already registered", "warning")
            return redirect(url_for("register"))

        hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")
        new_user = User(
            fullname=fullname,
            email=email,
            password=hashed_password,
            role=role
        )

        db.session.add(new_user)
        db.session.commit()

        log_security_event(f"User Registered: {email} (Role: {role})", user_id=new_user.id)
        
        # Auto-login upon registration for direct transition to dashboard
        login_user(new_user, remember=True)
        flash("Registration successful! Welcome to your CyberVault Dashboard.", "success")
        return redirect(url_for("dashboard"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        user = User.query.filter_by(email=email).first()

        if user and user.is_suspended:
            log_security_event(f"Suspended Account Login Attempt: {email}", status="BLOCKED")
            flash("Account is suspended. Please contact system administrator.", "danger")
            return redirect(url_for("login"))

        if user and bcrypt.check_password_hash(user.password, password):
            user.last_login = datetime.now().strftime("%d-%m-%Y %H:%M:%S")
            db.session.commit()
            login_user(user, remember=True)

            log_security_event(f"User Login Success: {email}", user_id=user.id)
            flash("Login successful! Welcome back.", "success")
            return redirect(url_for("dashboard"))

        log_security_event(f"Failed Login Attempt: {email}", status="FAILED")
        flash("Invalid email or password", "danger")
        return redirect(url_for("login"))

    return render_template("login.html")


@app.route("/auth/oauth/google")
def oauth_google():
    """Simulated OAuth 2.0 / Google SSO authentication flow."""
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    sso_email = "demo.google@cybervault.com"
    user = User.query.filter_by(email=sso_email).first()
    if not user:
        hashed_password = bcrypt.generate_password_hash("OAuthSecurePassword2026!").decode("utf-8")
        user = User(
            fullname="Google OAuth User",
            email=sso_email,
            password=hashed_password,
            role="user"
        )
        db.session.add(user)
        db.session.commit()

    user.last_login = datetime.now().strftime("%d-%m-%Y %H:%M:%S")
    db.session.commit()
    login_user(user)

    log_security_event("OAuth 2.0 Single Sign-On Success", user_id=user.id)
    flash("Authenticated via Google OAuth 2.0 SSO!", "success")
    return redirect(url_for("dashboard"))


@app.route("/dashboard")
@login_required
def dashboard():
    total_users = User.query.count()
    user_secrets = SecretVault.query.filter_by(user_id=current_user.id).order_by(SecretVault.created_at.desc()).all()

    # Pre-decrypt secrets for template display (with masked fallback)
    secrets_data = []
    for s in user_secrets:
        raw_val = s.get_decrypted_secret()
        secrets_data.append({
            "id": s.id,
            "title": s.title,
            "category": s.category,
            "decrypted_value": raw_val,
            "created_at": s.created_at.strftime("%Y-%m-%d %H:%M")
        })

    # Recent Audit logs
    if current_user.role == "admin":
        audit_logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(20).all()
        all_users = User.query.order_by(User.id.asc()).all()
    else:
        audit_logs = AuditLog.query.filter_by(user_id=current_user.id).order_by(AuditLog.timestamp.desc()).limit(10).all()
        all_users = []

    # Generate JWT token for dashboard API Studio tab
    user_jwt = generate_jwt(current_user)

    return render_template(
        "dashboard.html",
        user=current_user,
        total_users=total_users,
        secrets=secrets_data,
        audit_logs=audit_logs,
        all_users=all_users,
        user_jwt=user_jwt
    )


# ==========================
# Vault Management Routes
# ==========================

@app.route("/vault/add", methods=["POST"])
@login_required
def vault_add():
    title = request.form.get("title", "").strip()
    category = request.form.get("category", "API Key").strip()
    raw_secret = request.form.get("raw_secret", "").strip()

    if not title or not raw_secret:
        flash("Title and Secret value are required", "danger")
        return redirect(url_for("dashboard") + "#vault")

    new_secret = SecretVault(
        user_id=current_user.id,
        title=title,
        category=category
    )
    new_secret.set_secret(raw_secret)

    db.session.add(new_secret)
    db.session.commit()

    log_security_event(f"Encrypted Secret Added: {title} ({category})")
    flash(f"Secret '{title}' encrypted with AES-256 & saved to Vault!", "success")
    return redirect(url_for("dashboard") + "#vault")


@app.route("/vault/delete/<int:secret_id>", methods=["POST"])
@login_required
def vault_delete(secret_id):
    secret = db.session.get(SecretVault, secret_id)
    if not secret or secret.user_id != current_user.id:
        flash("Secret not found or access unauthorized", "danger")
        return redirect(url_for("dashboard") + "#vault")

    db.session.delete(secret)
    db.session.commit()

    log_security_event(f"Secret Deleted: {secret.title}")
    flash("Secret deleted from vault", "success")
    return redirect(url_for("dashboard") + "#vault")


# ==========================
# JWT API & Studio Endpoints
# ==========================

@app.route("/api/auth/token", methods=["POST", "GET"])
def api_token():
    """Generates a JWT token for API clients."""
    if request.method == "POST":
        data = request.get_json(silent=True, force=True)
        if not data or not isinstance(data, dict):
            data = request.form

        email = (data.get("email") or "").strip().lower()
        password = data.get("password") or ""

        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            token = generate_jwt(user)
            log_security_event(f"JWT Token Generated for API: {email}")
            return jsonify({"status": "success", "token": token, "token_type": "Bearer", "expires_in_hours": 2})

        return jsonify({"status": "error", "message": "Invalid API credentials"}), 401

    if current_user.is_authenticated:
        token = generate_jwt(current_user)
        return jsonify({"status": "success", "token": token, "token_type": "Bearer"})

    return jsonify({"status": "error", "message": "Authentication required"}), 401


@app.route("/api/secure-data", methods=["GET", "POST"])
def api_secure_data():
    """Protected API endpoint demonstrating JWT Bearer token authorization."""
    auth_header = request.headers.get("Authorization", "")
    token = None
    if auth_header.startswith("Bearer "):
        token = auth_header.split(" ")[1]

    if not token:
        return jsonify({"status": "unauthorized", "message": "Missing Bearer Token in Authorization header"}), 401

    try:
        payload = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
        return jsonify({
            "status": "authorized",
            "message": "Access granted to secure API payload",
            "authenticated_as": {
                "user_id": payload.get("sub"),
                "name": payload.get("name"),
                "email": payload.get("email"),
                "role": payload.get("role")
            },
            "security_encryption": "AES-256-GCM / HS256 JWT",
            "server_timestamp": datetime.utcnow().isoformat()
        }), 200
    except jwt.ExpiredSignatureError:
        return jsonify({"status": "unauthorized", "message": "JWT Token has expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"status": "unauthorized", "message": "Invalid JWT Token signature"}), 401


# ==========================
# Password Security & Breach Scanner API
# ==========================

COMMONLY_BREACHED_PASSWORDS = {
    "123456", "password", "123456789", "12345678", "12345", "1234567",
    "qwerty", "1234567890", "111111", "123123", "secret", "admin",
    "welcome", "login", "password1", "password123", "letmein", "monkey",
    "dragon", "master", "p@ssword", "abc123", "trustno1", "football",
    "shadow", "sunshine", "iloveyou", "princess", "superman"
}

@app.route("/api/password-scan", methods=["POST"])
def api_password_scan():
    """Password Security & Breach Scanner API."""
    import math
    data = request.get_json(silent=True, force=True)
    if not data or not isinstance(data, dict):
        data = request.form

    test_password = (data.get("password") or "").strip()
    if not test_password:
        return jsonify({
            "status": "ERROR",
            "score": 0,
            "crack_time": "Instant",
            "issues": [{"rule": "Empty Input", "description": "Please enter a password to scan."}],
            "recommendation": "Enter a password to evaluate its strength and breach risk."
        }), 400

    pwd_lower = test_password.lower()
    issues = []
    score = 100

    # 1. Known Breach / Weak Wordlist Check
    if pwd_lower in COMMONLY_BREACHED_PASSWORDS or any(w in pwd_lower for w in ["123456", "password", "qwerty", "admin", "welcome"]):
        score -= 60
        issues.append({
            "rule": "Known Breached / Common Password",
            "severity": "CRITICAL",
            "description": "Password appears in public data breaches and common dictionary attack lists."
        })

    # 2. Length Check
    length = len(test_password)
    if length < 8:
        score -= 30
        issues.append({
            "rule": "Short Password Length",
            "severity": "HIGH",
            "description": f"Password is too short ({length} chars). Minimum recommended length is 12+ characters."
        })
    elif length < 12:
        score -= 10
        issues.append({
            "rule": "Moderate Password Length",
            "severity": "MEDIUM",
            "description": f"Length is {length} characters. Increasing to 14+ characters significantly boosts crack time."
        })

    # 3. Character Complexity Checks
    has_upper = bool(re.search(r"[A-Z]", test_password))
    has_lower = bool(re.search(r"[a-z]", test_password))
    has_digit = bool(re.search(r"\d", test_password))
    has_symbol = bool(re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>/?~`]", test_password))

    if not has_upper:
        score -= 10
        issues.append({"rule": "Missing Uppercase", "severity": "LOW", "description": "Add uppercase letters (A-Z)."})
    if not has_lower:
        score -= 10
        issues.append({"rule": "Missing Lowercase", "severity": "LOW", "description": "Add lowercase letters (a-z)."})
    if not has_digit:
        score -= 10
        issues.append({"rule": "Missing Numbers", "severity": "LOW", "description": "Add numbers (0-9)."})
    if not has_symbol:
        score -= 15
        issues.append({"rule": "Missing Symbols", "severity": "MEDIUM", "description": "Add special symbols (!@#$%^&*)."})

    # 4. Pattern & Repeat Analysis
    if re.search(r"(.)\1{2,}", test_password):
        score -= 10
        issues.append({"rule": "Repeated Characters", "severity": "LOW", "description": "Avoid repeating characters (e.g. 'aaa')."})

    if re.search(r"(123|234|345|456|567|678|789|abc|bcd|cde|qwer|asdf)", pwd_lower):
        score -= 15
        issues.append({"rule": "Sequential Pattern", "severity": "MEDIUM", "description": "Contains predictable sequence ('123' or 'qwerty')."})

    score = max(0, min(100, score))

    # Calculate estimated crack time
    charset_size = 0
    if has_lower: charset_size += 26
    if has_upper: charset_size += 26
    if has_digit: charset_size += 10
    if has_symbol: charset_size += 32
    if charset_size == 0: charset_size = 26

    guesses = (charset_size ** length) / 2
    seconds = guesses / 10_000_000_000  # 10 billion guesses/sec

    if score < 40 or seconds < 1:
        crack_time = "Instant (< 1 second)"
        status = "WEAK / LEAKED"
        recommendation = "CRITICAL: Change this password immediately! Use a combination of uppercase, numbers, and symbols."
    elif seconds < 60:
        crack_time = f"{int(seconds)} seconds"
        status = "WEAK"
        recommendation = "Weak password! Easily cracked by automated brute-force scripts."
    elif seconds < 3600:
        crack_time = f"{int(seconds // 60)} minutes"
        status = "FAIR"
        recommendation = "Fair password, but vulnerable to targeted dictionary attacks."
    elif seconds < 86400 * 365:
        crack_time = f"{int(seconds // 86400)} days"
        status = "GOOD"
        recommendation = "Good password. Consider increasing length for maximum longevity."
    else:
        years = int(seconds // (86400 * 365))
        if years > 1_000_000:
            crack_time = "1,000,000+ Years"
        else:
            crack_time = f"{years:,} Years"
        status = "STRONG"
        recommendation = "EXCELLENT! High entropy password resistant to brute-force attacks."

    log_security_event(f"Password Scan Executed (Status: {status}, Score: {score}/100)")

    return jsonify({
        "status": status,
        "score": score,
        "length": length,
        "crack_time": crack_time,
        "complexity": {
            "has_upper": has_upper,
            "has_lower": has_lower,
            "has_digit": has_digit,
            "has_symbol": has_symbol
        },
        "issues": issues,
        "recommendation": recommendation
    })


# ==========================
# Malicious Code & Input Security Scanner API
# ==========================

@app.route("/api/input-scan", methods=["POST"])
def api_input_scan():
    """Malicious Code & Input Security Scanner Engine."""
    data = request.get_json(silent=True, force=True)
    if not data or not isinstance(data, dict):
        data = request.form

    raw_input = (data.get("input_text") or data.get("text") or "").strip()
    if not raw_input:
        return jsonify({
            "status": "ERROR",
            "threat_score": 0,
            "threat_level": "NONE",
            "threats_found": [{"type": "Empty Input", "severity": "INFO", "description": "Please enter text or code payload to analyze."}],
            "recommendation": "Enter a string or code snippet to scan for SQLi, XSS, and Command Injection."
        }), 400

    threats = []
    safety_score = 100

    # 1. SQL Injection (SQLi) Patterns
    sqli_patterns = [
        (r"(\'|\")\s*(OR|AND)\s*(\'|\")?\s*(\d+|\w+)\s*=\s*(\'|\")?\s*(\d+|\w+)", "SQLi Tautology Pattern (' OR '1'='1)", "CRITICAL", "Attempts to bypass authentication queries by forcing a TRUE evaluation."),
        (r"\b(UNION\s+SELECT|UNION\s+ALL\s+SELECT)\b", "SQLi UNION Attack Keyword", "CRITICAL", "Attempts to append unauthorized query results to existing database responses."),
        (r"\b(DROP\s+TABLE|DROP\s+DATABASE|TRUNCATE\s+TABLE)\b", "SQLi Database Destruction Query", "CRITICAL", "Attempts to destroy or truncate database structures."),
        (r"(--|\/\*|\*\/|;\s*SELECT|;\s*INSERT|;\s*UPDATE)", "SQL Inline Comment / Query Separator", "HIGH", "Uses SQL comment delimiters to truncate query execution.")
    ]

    for pattern, rule_name, severity, desc in sqli_patterns:
        if re.search(pattern, raw_input, re.IGNORECASE):
            safety_score -= 30
            threats.append({"type": "SQL Injection (SQLi)", "rule": rule_name, "severity": severity, "description": desc})

    # 2. Cross-Site Scripting (XSS) Patterns
    xss_patterns = [
        (r"<\s*script[^>]*>", "XSS <script> Tag Injection", "CRITICAL", "Injects executable JavaScript tag into client-side browser DOM."),
        (r"javascript\s*:", "XSS JavaScript URI Scheme", "HIGH", "Executes inline script via URL scheme attribute."),
        (r"\bon\w+\s*=\s*(\'|\"|`)[^'\"]*(\'|\"|`)", "XSS Event Handler Attribute (onerror/onload)", "HIGH", "Triggers script execution on DOM events."),
        (r"<\s*iframe[^>]*>", "XSS Malicious iFrame Injection", "HIGH", "Embeds untrusted external frame content into host document.")
    ]

    for pattern, rule_name, severity, desc in xss_patterns:
        if re.search(pattern, raw_input, re.IGNORECASE):
            safety_score -= 25
            threats.append({"type": "Cross-Site Scripting (XSS)", "rule": rule_name, "severity": severity, "description": desc})

    # 3. OS Command Injection Patterns
    cmd_patterns = [
        (r"(;|\&\&|\|\|)\s*(rm\s+-rf|cat\s+/etc/passwd|shutdown|format|wget|curl|nc\s+)", "OS Command Chaining Payload", "CRITICAL", "Attempts to execute arbitrary system shell commands on the server OS."),
        (r"\b(powershell\s+-enc|cmd\.exe\s+/c|/bin/sh|/bin/bash)\b", "Shell Interpreter Execution Call", "CRITICAL", "Spawns interactive shell environment executable.")
    ]

    for pattern, rule_name, severity, desc in cmd_patterns:
        if re.search(pattern, raw_input, re.IGNORECASE):
            safety_score -= 35
            threats.append({"type": "OS Command Injection", "rule": rule_name, "severity": severity, "description": desc})

    # 4. Path Traversal (LFI / RFI) Patterns
    path_patterns = [
        (r"(\.\./\.\./|\.\.\\\.\.\\|/etc/passwd|c:\\windows\\system32)", "Path Traversal (LFI) File Path", "HIGH", "Attempts to traverse directory tree to read restricted system files.")
    ]

    for pattern, rule_name, severity, desc in path_patterns:
        if re.search(pattern, raw_input, re.IGNORECASE):
            safety_score -= 25
            threats.append({"type": "Directory Path Traversal", "rule": rule_name, "severity": severity, "description": desc})

    safety_score = max(0, min(100, safety_score))

    if safety_score >= 85:
        status = "SAFE"
        threat_level = "CLEAN"
        recommendation = "Input text is clean and safe. No malicious code or injection patterns detected."
    elif safety_score >= 50:
        status = "SUSPICIOUS_CODE_DETECTED"
        threat_level = "MEDIUM"
        recommendation = "Suspicious code patterns detected. Sanitize input with HTML entity escaping and Jinja2 autoescaping."
    else:
        status = "MALICIOUS_CODE_ALERT"
        threat_level = "CRITICAL"
        recommendation = "DANGER! Malicious injection payload identified. Block payload execution immediately!"

    log_security_event(f"Input Code Scan Executed (Status: {status}, Score: {safety_score}/100)")

    return jsonify({
        "status": status,
        "threat_score": safety_score,
        "threat_level": threat_level,
        "input_preview": raw_input[:100],
        "threats_found": threats,
        "recommendation": recommendation
    })


# ==========================
# Phishing & Safe URL Scanner API
# ==========================

@app.route("/api/url-scan", methods=["POST"])
@app.route("/api/scan", methods=["POST"])
def api_url_scan():
    """Phishing & Safe URL Security Scanner Engine."""
    data = request.get_json(silent=True, force=True)
    if not data or not isinstance(data, dict):
        data = request.form

    target_url = (data.get("url") or data.get("input_text") or "").strip()
    if not target_url:
        return jsonify({
            "status": "ERROR",
            "threat_score": 0,
            "risk_level": "UNKNOWN",
            "threats_found": [{"rule": "Empty Input", "type": "WARNING", "description": "Please enter a valid web URL to scan."}],
            "recommendation": "Enter a full web URL like 'https://google.com' or 'http://paypal-security.xyz/login'."
        }), 400

    # Format URL scheme for parsing
    formatted_url = target_url
    if not formatted_url.startswith(("http://", "https://")):
        formatted_url = "http://" + formatted_url

    try:
        parsed = urlparse(formatted_url)
        domain = parsed.netloc.lower() if parsed.netloc else target_url.lower()
        path = parsed.path.lower() if parsed.path else ""
    except Exception:
        parsed = urlparse("http://" + target_url)
        domain = target_url.lower()
        path = ""

    threats = []
    safety_score = 100

    # 1. Check for Raw IP Address in Host (High Phishing Risk)
    ip_pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    if re.match(ip_pattern, domain):
        safety_score -= 40
        threats.append({
            "rule": "Raw IP Address Hostname",
            "type": "HIGH_RISK",
            "description": "URL uses a raw IP address hostname instead of a registered domain name, a technique frequently used by phishing bots."
        })

    # 2. Check for Brand Typosquatting & Phishing Keywords
    phishing_keywords = [
        "paypal", "bank", "verify", "secure", "login", "signin", "account",
        "update", "appleid", "amazon", "netflix", "microsoft", "confirm",
        "wallet", "crypto", "support"
    ]
    trusted_domains = ["paypal.com", "bankofamerica.com", "apple.com", "amazon.com", "netflix.com", "microsoft.com", "google.com", "github.com"]
    is_trusted = any(domain == td or domain.endswith("." + td) for td in trusted_domains)

    if not is_trusted:
        matched_keywords = [kw for kw in phishing_keywords if kw in domain or kw in path]
        if len(matched_keywords) >= 2 or ("-" in domain and any(kw in domain for kw in phishing_keywords)):
            safety_score -= 45
            threats.append({
                "rule": "Brand Mimicking & Phishing Keywords",
                "type": "PHISHING_ALERT",
                "description": f"Domain contains suspicious phishing keywords ({', '.join(matched_keywords)}) attempting to trick users into trusting a fake site."
            })
        elif len(matched_keywords) == 1:
            safety_score -= 20
            threats.append({
                "rule": "Suspicious Sensitive Keyword",
                "type": "SUSPICIOUS",
                "description": f"Domain includes sensitive keyword '{matched_keywords[0]}'."
            })

    # 3. Check for Suspicious Top-Level Domains (TLDs)
    high_risk_tlds = [".xyz", ".top", ".zip", ".club", ".work", ".cam", ".kim", ".info", ".tk", ".ml", ".ga", ".cf", ".gq"]
    if any(domain.endswith(tld) for tld in high_risk_tlds):
        safety_score -= 25
        threats.append({
            "rule": "High-Risk Top-Level Domain (TLD)",
            "type": "SUSPICIOUS_TLD",
            "description": "URL uses a TLD frequently associated with spam, malware, and phishing campaigns."
        })

    # 4. Check for Unencrypted HTTP on Sensitive Login Paths
    if parsed.scheme == "http" and any(k in path or k in domain for k in ["login", "bank", "verify", "secure", "account"]):
        safety_score -= 20
        threats.append({
            "rule": "Unencrypted HTTP Protocol",
            "type": "INSECURE_PROTOCOL",
            "description": "Sensitive login/banking page transmitted over unencrypted HTTP protocol without SSL/TLS encryption."
        })

    # 5. Excessive Subdomain Depth
    subdomain_parts = domain.split(".")
    if len(subdomain_parts) >= 4:
        safety_score -= 20
        threats.append({
            "rule": "Excessive Subdomain Chaining",
            "type": "SUBDOMAIN_ABUSE",
            "description": "Multiple subdomains chained together to obscure the real target domain."
        })

    safety_score = max(0, min(100, safety_score))

    if safety_score >= 80:
        status = "SAFE"
        risk_level = "LOW"
        recommendation = "This URL appears legitimate and safe to visit."
    elif safety_score >= 50:
        status = "SUSPICIOUS"
        risk_level = "MEDIUM"
        recommendation = "Proceed with caution. Verify the domain name carefully before entering any personal info."
    else:
        status = "PHISHING_ALERT"
        risk_level = "HIGH"
        recommendation = "DANGER! High probability of a phishing or fraudulent website. DO NOT enter passwords or financial data."

    log_security_event(f"URL Scan Executed: {target_url} (Result: {status}, Score: {safety_score})")

    return jsonify({
        "status": status,
        "threat_score": safety_score,
        "risk_level": risk_level,
        "url": target_url,
        "domain": domain,
        "scheme": parsed.scheme.upper(),
        "threats_found": threats,
        "recommendation": recommendation
    })


# ==========================
# Admin Management Routes
# ==========================

@app.route("/admin/user/<int:user_id>/toggle-role", methods=["POST"])
@login_required
@admin_required
def admin_toggle_role(user_id):
    user = db.session.get(User, user_id)
    if not user:
        flash("User not found", "danger")
        return redirect(url_for("dashboard"))

    if user.id == current_user.id:
        flash("You cannot change your own admin role", "warning")
        return redirect(url_for("dashboard"))

    new_role = "admin" if user.role == "user" else "user"
    user.role = new_role
    db.session.commit()

    log_security_event(f"Admin Role Changed for {user.email} -> {new_role}")
    flash(f"User '{user.fullname}' role updated to '{new_role}'", "success")
    return redirect(url_for("dashboard") + "#admin")


@app.route("/admin/user/<int:user_id>/toggle-status", methods=["POST"])
@login_required
@admin_required
def admin_toggle_status(user_id):
    user = db.session.get(User, user_id)
    if not user:
        flash("User not found", "danger")
        return redirect(url_for("dashboard"))

    if user.id == current_user.id:
        flash("You cannot suspend your own account", "warning")
        return redirect(url_for("dashboard"))

    user.is_suspended = not user.is_suspended
    db.session.commit()

    status_str = "Suspended" if user.is_suspended else "Activated"
    log_security_event(f"Admin Status Change for {user.email} -> {status_str}")
    flash(f"User '{user.fullname}' account status set to '{status_str}'", "warning" if user.is_suspended else "success")
    return redirect(url_for("dashboard") + "#admin")


# ==========================
# Profile & Password Routes
# ==========================

@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    if request.method == "POST":
        fullname = request.form.get("fullname", "").strip()
        email = request.form.get("email", "").strip().lower()

        if not fullname:
            flash("Full Name cannot be empty", "danger")
            return redirect(url_for("profile"))

        if not is_valid_email(email):
            flash("Please enter a valid email address", "danger")
            return redirect(url_for("profile"))

        existing_user = User.query.filter(
            User.email == email,
            User.id != current_user.id
        ).first()

        if existing_user:
            flash("Email address is already in use by another account", "danger")
            return redirect(url_for("profile"))

        current_user.fullname = fullname
        current_user.email = email
        db.session.commit()

        log_security_event("Profile Updated Successfully")
        flash("Profile updated successfully", "success")
        return redirect(url_for("profile"))

    return render_template("profile.html", user=current_user)


@app.route("/change_password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "POST":
        old_password = request.form.get("old_password", "")
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not bcrypt.check_password_hash(current_user.password, old_password):
            log_security_event("Password Change Failed: Wrong Old Password", status="FAILED")
            flash("Current password is incorrect", "danger")
            return redirect(url_for("change_password"))

        if new_password != confirm_password:
            flash("New passwords do not match", "danger")
            return redirect(url_for("change_password"))

        is_valid, err_msg = validate_password(new_password)
        if not is_valid:
            flash(err_msg, "danger")
            return redirect(url_for("change_password"))

        current_user.password = bcrypt.generate_password_hash(new_password).decode("utf-8")
        db.session.commit()

        log_security_event("Password Updated Successfully")
        flash("Password updated successfully!", "success")
        return redirect(url_for("dashboard"))

    return render_template("change_password.html")


@app.route("/logout")
@login_required
def logout():
    log_security_event("User Logged Out")
    logout_user()
    flash("Logged out successfully.", "success")
    return redirect(url_for("login"))


# ==========================
# Database Initialization & Admin Seeding
# ==========================

with app.app_context():
    db.create_all()

    # Seed Default Admin Account if not exists
    admin_user = User.query.filter_by(email="admin@cybervault.com").first()
    if not admin_user:
        hashed_admin_pass = bcrypt.generate_password_hash("Admin@123456").decode("utf-8")
        default_admin = User(
            fullname="System Administrator",
            email="admin@cybervault.com",
            password=hashed_admin_pass,
            role="admin"
        )
        db.session.add(default_admin)
        db.session.commit()


# ==========================
# Run Application
# ==========================

if __name__ == "__main__":
    app.run(debug=True)