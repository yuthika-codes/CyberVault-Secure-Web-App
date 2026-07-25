import os
import re
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash
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

# ==========================
# Create Flask App
# ==========================

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "cybervault_secure_secret_key_2026")
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False


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
# User Model
# ==========================

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    fullname = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    last_login = db.Column(db.String(100), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


# ==========================
# Load User Callback
# ==========================

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


# ==========================
# Security & Validation Helpers
# ==========================

def is_valid_email(email):
    """Validate email format using standard regex pattern."""
    pattern = r"^[\w\.-]+@[\w\.-]+\.\w+$"
    return bool(re.match(pattern, email))


def validate_password(password):
    """
    Validates password strength:
    - Minimum 8 characters
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one digit
    - At least one special character (!@#$%^&*)
    """
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


# ==========================
# Security Headers Middleware
# ==========================

@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
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
# Routes
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

        if not fullname:
            flash("Full Name is required", "danger")
            return redirect(url_for("register"))

        if not is_valid_email(email):
            flash("Please enter a valid email address", "danger")
            return redirect(url_for("register"))

        # Password Strength Validation
        is_valid, err_msg = validate_password(password)
        if not is_valid:
            flash(err_msg, "danger")
            return redirect(url_for("register"))

        if password != confirm_password:
            flash("Passwords do not match", "danger")
            return redirect(url_for("register"))

        # Check Existing User
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash("Email address is already registered", "warning")
            return redirect(url_for("register"))

        # Hash Password and Create User
        hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")
        new_user = User(
            fullname=fullname,
            email=email,
            password=hashed_password
        )

        db.session.add(new_user)
        db.session.commit()

        flash("Registration successful! Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        user = User.query.filter_by(email=email).first()

        if user and bcrypt.check_password_hash(user.password, password):
            user.last_login = datetime.now().strftime("%d-%m-%Y %H:%M:%S")
            db.session.commit()
            login_user(user)

            flash("Login successful! Welcome back.", "success")
            return redirect(url_for("dashboard"))

        flash("Invalid email or password", "danger")
        return redirect(url_for("login"))

    return render_template("login.html")


@app.route("/dashboard")
@login_required
def dashboard():
    total_users = User.query.count()
    return render_template(
        "dashboard.html",
        user=current_user,
        total_users=total_users
    )


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
            flash("Current password is incorrect", "danger")
            return redirect(url_for("change_password"))

        if new_password != confirm_password:
            flash("New passwords do not match", "danger")
            return redirect(url_for("change_password"))

        # Enforce Password Complexity on Password Change
        is_valid, err_msg = validate_password(new_password)
        if not is_valid:
            flash(err_msg, "danger")
            return redirect(url_for("change_password"))

        current_user.password = bcrypt.generate_password_hash(new_password).decode("utf-8")
        db.session.commit()

        flash("Password updated successfully!", "success")
        return redirect(url_for("dashboard"))

    return render_template("change_password.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out successfully.", "success")
    return redirect(url_for("login"))


# ==========================
# Database Initialization
# ==========================

with app.app_context():
    db.create_all()


# ==========================
# Run Application
# ==========================

if __name__ == "__main__":
    app.run(debug=True)