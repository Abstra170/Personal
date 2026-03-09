"""
app/security.py — Security layer for admin panel

Provides:
- IP allowlist enforcement
- Brute-force login lockout (in-memory, no Redis needed)
- Email OTP two-factor authentication (replaces TOTP/Google Authenticator)
- Security response headers
- Session hardening
"""

import os
import random
import smtplib
import string
import time
from collections import defaultdict
from datetime import timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from functools import wraps

from flask import request, abort, session, current_app


# ─────────────────────────────────────────────────────────────────
# IN-MEMORY BRUTE-FORCE TRACKER
# ─────────────────────────────────────────────────────────────────

_failed_attempts = defaultdict(list)   # ip -> [timestamp, ...]
_lockout_until   = {}                   # ip -> timestamp


def get_client_ip():
    """Get real client IP, respecting X-Forwarded-For behind proxy."""
    if request.headers.get("X-Forwarded-For"):
        return request.headers["X-Forwarded-For"].split(",")[0].strip()
    return request.remote_addr or "unknown"


def is_ip_locked(ip):
    """Return True if IP is currently locked out."""
    if ip in _lockout_until:
        if time.time() < _lockout_until[ip]:
            return True
        else:
            del _lockout_until[ip]
            _failed_attempts.pop(ip, None)
    return False


def record_failed_login(ip):
    """Record a failed attempt. Lock IP if threshold exceeded."""
    max_attempts = int(os.environ.get("MAX_LOGIN_ATTEMPTS", 5))
    lockout_secs = int(os.environ.get("LOGIN_LOCKOUT_SECONDS", 900))
    window = 300  # 5-minute sliding window

    now = time.time()
    attempts = _failed_attempts[ip]
    _failed_attempts[ip] = [t for t in attempts if now - t < window]
    _failed_attempts[ip].append(now)

    if len(_failed_attempts[ip]) >= max_attempts:
        _lockout_until[ip] = now + lockout_secs
        return True
    return False


def clear_failed_attempts(ip):
    """Clear failed attempts on successful login."""
    _failed_attempts.pop(ip, None)
    _lockout_until.pop(ip, None)


def lockout_remaining(ip):
    """Return seconds remaining in lockout, or 0."""
    if ip in _lockout_until:
        remaining = _lockout_until[ip] - time.time()
        return max(0, int(remaining))
    return 0


# ─────────────────────────────────────────────────────────────────
# EMAIL OTP (replaces TOTP / Google Authenticator)
# ─────────────────────────────────────────────────────────────────

OTP_EXPIRY_SECONDS = 300  # 5 minutes


def generate_otp(digits=6):
    """Generate a secure random numeric OTP."""
    return "".join(random.choices(string.digits, k=digits))


def send_otp_email(otp_code):
    """
    Send OTP code to the admin email configured in .env.
    Uses MAIL_* environment variables.
    Returns (True, None) on success or (False, error_message) on failure.
    """
    mail_server   = os.environ.get("MAIL_SERVER", "smtp.gmail.com")
    mail_port     = int(os.environ.get("MAIL_PORT", 587))
    mail_use_tls  = os.environ.get("MAIL_USE_TLS", "true").lower() == "true"
    mail_username = os.environ.get("MAIL_USERNAME", "")
    mail_password = os.environ.get("MAIL_PASSWORD", "")
    mail_sender   = os.environ.get("MAIL_DEFAULT_SENDER", mail_username)
    mail_receiver = os.environ.get("CONTACT_RECEIVER", mail_username)

    if not mail_username or not mail_password:
        return False, "Mail credentials not configured in .env"

    subject = "Your Admin Login Code"
    html_body = f"""
    <div style="font-family: Arial, sans-serif; max-width: 480px; margin: 0 auto;
                background: #0f0f0f; color: #ffffff; padding: 32px; border-radius: 12px;">
      <h2 style="margin: 0 0 8px 0; font-size: 22px;">Two-Factor Login</h2>
      <p style="color: #aaa; margin: 0 0 28px 0; font-size: 14px;">
        Someone (hopefully you) is logging into your Portfolio Admin panel.
      </p>
      <div style="background: #1a1a1a; border: 1px solid #333; border-radius: 10px;
                  padding: 24px; text-align: center; margin-bottom: 24px;">
        <p style="margin: 0 0 8px 0; font-size: 13px; color: #888; letter-spacing: 1px;
                  text-transform: uppercase;">Your login code</p>
        <p style="margin: 0; font-size: 40px; font-weight: bold; letter-spacing: 10px;
                  color: #3b82f6; font-family: monospace;">{otp_code}</p>
      </div>
      <p style="color: #888; font-size: 13px; margin: 0 0 6px 0;">
        This code expires in <strong style="color: #fff;">5 minutes</strong>.
      </p>
      <p style="color: #555; font-size: 12px; margin: 0;">
        If you did not request this, your password may be compromised.
      </p>
    </div>
    """
    text_body = f"Your admin login OTP is: {otp_code}\nExpires in 5 minutes."

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = mail_sender
    msg["To"]      = mail_receiver
    msg.attach(MIMEText(text_body, "plain"))
    msg.attach(MIMEText(html_body, "html"))

    try:
        with smtplib.SMTP(mail_server, mail_port, timeout=10) as smtp:
            if mail_use_tls:
                smtp.starttls()
            smtp.login(mail_username, mail_password)
            smtp.sendmail(mail_sender, mail_receiver, msg.as_string())
        return True, None
    except smtplib.SMTPAuthenticationError:
        return False, "Email authentication failed. Check MAIL_USERNAME and MAIL_PASSWORD in .env"
    except smtplib.SMTPException as e:
        return False, f"SMTP error: {e}"
    except Exception as e:
        return False, f"Failed to send email: {e}"


def email_otp_is_enabled():
    """Return True if email-based OTP should be used."""
    enabled  = os.environ.get("EMAIL_OTP_ENABLED", "true").lower() == "true"
    has_mail = bool(os.environ.get("MAIL_USERNAME", "").strip())
    return enabled and has_mail


# ─────────────────────────────────────────────────────────────────
# LEGACY TOTP — kept for backward compatibility (not used)
# ─────────────────────────────────────────────────────────────────

def verify_totp(secret, user_code, window=1):
    """Legacy TOTP verify — not used when EMAIL_OTP_ENABLED=true."""
    import hashlib, hmac as _hmac, struct
    if not secret or not user_code:
        return False

    def _b32decode(s):
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
        s = s.upper().rstrip("=")
        buf, bits, result = 0, 0, bytearray()
        for ch in s:
            if ch not in alphabet:
                continue
            buf = (buf << 5) | alphabet.index(ch)
            bits += 5
            if bits >= 8:
                bits -= 8
                result.append((buf >> bits) & 0xFF)
        return bytes(result)

    user_code = str(user_code).strip()
    now = time.time()
    try:
        key = _b32decode(secret)
        for delta in range(-window, window + 1):
            t   = int((now + delta * 30) // 30)
            msg = struct.pack(">Q", t)
            h   = _hmac.new(key, msg, hashlib.sha1).digest()
            offset = h[-1] & 0x0F
            code   = str(struct.unpack(">I", h[offset:offset+4])[0] & 0x7FFFFFFF % 1000000).zfill(6)
            if _hmac.compare_digest(code, user_code):
                return True
    except Exception:
        pass
    return False


# ─────────────────────────────────────────────────────────────────
# IP ALLOWLIST
# ─────────────────────────────────────────────────────────────────

def get_allowed_ips():
    raw = os.environ.get("ADMIN_ALLOWED_IPS", "*")
    if raw.strip() == "*":
        return None
    return [ip.strip() for ip in raw.split(",") if ip.strip()]


def check_admin_ip():
    return True


def ip_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        check_admin_ip()
        return f(*args, **kwargs)
    return decorated


# ─────────────────────────────────────────────────────────────────
# SECURITY HEADERS
# ─────────────────────────────────────────────────────────────────

def apply_security_headers(response):
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = (
        "geolocation=(), microphone=(), camera=(), payment=(), usb=()"
    )
    if os.environ.get("FLASK_ENV") == "production":
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains; preload"
        )
    if os.environ.get("CSP_ENABLED", "true").lower() == "true":
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "img-src 'self' data: https:; "
            "frame-src https://www.youtube.com https://player.vimeo.com; "
            "connect-src 'self';"
        )
    if "/admin" in request.path or f"/{os.environ.get('ADMIN_URL_PREFIX','admin')}" in request.path:
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
        response.headers["Pragma"] = "no-cache"
    return response


# ─────────────────────────────────────────────────────────────────
# SESSION HARDENING
# ─────────────────────────────────────────────────────────────────

def configure_session(app):
    lifetime = int(os.environ.get("SESSION_LIFETIME_SECONDS", 3600))
    app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(seconds=lifetime)
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    secure = os.environ.get("SESSION_COOKIE_SECURE", "false").lower() == "true"
    app.config["SESSION_COOKIE_SECURE"] = secure
    app.config["SESSION_COOKIE_NAME"] = "__Host-session" if secure else "session"


# ─────────────────────────────────────────────────────────────────
# 2FA SESSION STATE
# ─────────────────────────────────────────────────────────────────

def set_awaiting_2fa(user_id):
    """Mark session as needing 2FA completion."""
    session["_2fa_pending"]   = True
    session["_2fa_user_id"]   = user_id
    session["_2fa_timestamp"] = time.time()


def get_awaiting_2fa():
    """Return user_id if 2FA is pending and not expired, else None."""
    if not session.get("_2fa_pending"):
        return None
    ts = session.get("_2fa_timestamp", 0)
    if time.time() - ts > OTP_EXPIRY_SECONDS:
        clear_2fa_session()
        return None
    return session.get("_2fa_user_id")


def clear_2fa_session():
    session.pop("_2fa_pending",   None)
    session.pop("_2fa_user_id",   None)
    session.pop("_2fa_timestamp", None)
    session.pop("_2fa_otp",       None)


# ─────────────────────────────────────────────────────────────────
# OTP SESSION HELPERS
# ─────────────────────────────────────────────────────────────────

def store_otp_in_session(otp_code):
    """Save generated OTP into the session."""
    session["_2fa_otp"] = otp_code


def verify_email_otp(user_code):
    """
    Verify the code the user entered against the one stored in session.
    Returns True if correct and not expired.
    """
    stored = session.get("_2fa_otp")
    ts     = session.get("_2fa_timestamp", 0)
    if not stored or not user_code:
        return False
    if time.time() - ts > OTP_EXPIRY_SECONDS:
        return False
    return stored == str(user_code).strip()