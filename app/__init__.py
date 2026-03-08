import os
from pathlib import Path
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect
from .extensions import mail

db = SQLAlchemy()
login_manager = LoginManager()
csrf = CSRFProtect()



def _load_env():
    """Manually load .env file — works on Windows and Linux."""
    env_path = Path(__file__).parent.parent / ".env"
    if not env_path.exists():
        return
    with open(env_path, encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key and key not in os.environ:
                os.environ[key] = value


def create_app():
    _load_env()

    app = Flask(
        __name__,
        template_folder="views/templates",
        static_folder="views/static",
    )


    # ── Core config ───────────────────────────────────────────────
    secret_key = os.environ.get("SECRET_KEY", "")
    if not secret_key or "change-this" in secret_key:
        import secrets
        secret_key = secrets.token_hex(48)
        print("WARNING: No SECRET_KEY in .env — generated a temporary one.")

    app.config["SECRET_KEY"] = secret_key
    app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:///portfolio.db")
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024

    app.config["MAIL_SERVER"] = os.getenv("MAIL_SERVER")
    app.config["MAIL_PORT"] = int(os.getenv("MAIL_PORT", 587))
    app.config["MAIL_USE_TLS"] = os.getenv("MAIL_USE_TLS", "True") == "True"
    app.config["MAIL_USERNAME"] = os.getenv("MAIL_USERNAME")
    app.config["MAIL_PASSWORD"] = os.getenv("MAIL_PASSWORD")
    app.config["MAIL_DEFAULT_SENDER"] = os.getenv("MAIL_DEFAULT_SENDER")

    mail.init_app(app)

    # ── Session security ──────────────────────────────────────────
    from app.security import configure_session
    configure_session(app)

    # ── Extensions ────────────────────────────────────────────────
    db.init_app(app)
    csrf.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = "admin.login"
    login_manager.login_message = None

    # ── Security headers ──────────────────────────────────────────
    from app.security import apply_security_headers
    app.after_request(apply_security_headers)

    # ── Blueprints ────────────────────────────────────────────────
    from app.controllers.public import public_bp
    from app.controllers.admin import admin_bp

    admin_prefix = "/" + os.environ.get("ADMIN_URL_PREFIX", "secret-admin-panel")
    app.register_blueprint(public_bp)
    app.register_blueprint(admin_bp, url_prefix=admin_prefix)
    app.config["ADMIN_URL_PREFIX"] = admin_prefix.lstrip("/")

    # ── DB + seed ─────────────────────────────────────────────────
    with app.app_context():
        db.create_all()
        _seed_admin()

    return app


def _seed_admin():
    from app.models.user import User
    from werkzeug.security import generate_password_hash

    if User.query.first():
        return

    username = os.environ.get("ADMIN_USERNAME", "admin")
    password = os.environ.get("ADMIN_PASSWORD", "")

    if not password or "your-strong-password" in password:
        import secrets
        password = secrets.token_urlsafe(18)
        print(f"\n{'='*52}")
        print("  WARNING: No ADMIN_PASSWORD in .env!")
        print(f"  Auto-generated password: {password}")
        print(f"  Username: {username}")
        print("  Save these now!")
        print(f"{'='*52}\n")

    admin = User(
        username=username,
        password_hash=generate_password_hash(password, method="pbkdf2:sha256:600000"),
    )
    db.session.add(admin)
    db.session.commit()
    admin_prefix = os.environ.get("ADMIN_URL_PREFIX", "secret-admin-panel")
    print(f"Admin created: {username}")
    print(f"Admin URL: /{admin_prefix}/login")
    print("Run: python setup_2fa.py  (to enable 2FA)")
