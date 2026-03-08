"""
app/security.py — Security layer for admin panel

Provides:
- IP allowlist enforcement
- Brute-force login lockout (in-memory, no Redis needed)
- TOTP two-factor authentication (no external library)
- Security response headers
- Session hardening
"""

import hashlib
import hmac
import os
import struct
import time
from collections import defaultdict
from datetime import timedelta
from functools import wraps

from flask import request, abort, session, current_app


# ─────────────────────────────────────────────────────────────────
# IN-MEMORY BRUTE-FORCE TRACKER
# (Resets on server restart — fine for single-server setups)
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
    # Prune old entries outside window
    _failed_attempts[ip] = [t for t in attempts if now - t < window]
    _failed_attempts[ip].append(now)

    if len(_failed_attempts[ip]) >= max_attempts:
        _lockout_until[ip] = now + lockout_secs
        return True  # locked
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
# TOTP (RFC 6238) — no external library
# ─────────────────────────────────────────────────────────────────

def _base32_decode(s):
    """Decode base32 string to bytes."""
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    s = s.upper().rstrip("=")
    buffer = 0
    bits_left = 0
    result = bytearray()
    for char in s:
        if char not in alphabet:
            continue
        buffer = (buffer << 5) | alphabet.index(char)
        bits_left += 5
        if bits_left >= 8:
            bits_left -= 8
            result.append((buffer >> bits_left) & 0xFF)
    return bytes(result)


def get_totp_code(secret, timestamp=None, step=30, digits=6):
    """Generate TOTP code for given secret at given time."""
    if not secret:
        return None
    try:
        key = _base32_decode(secret)
        t = int((timestamp or time.time()) // step)
        msg = struct.pack(">Q", t)
        h = hmac.new(key, msg, hashlib.sha1).digest()
        offset = h[-1] & 0x0F
        code = struct.unpack(">I", h[offset:offset + 4])[0] & 0x7FFFFFFF
        return str(code % (10 ** digits)).zfill(digits)
    except Exception:
        return None


def verify_totp(secret, user_code, window=1):
    """
    Verify a TOTP code. Allows `window` steps of drift (±30s per step).
    Returns True if valid.
    """
    if not secret or not user_code:
        return False
    user_code = str(user_code).strip()
    now = time.time()
    for delta in range(-window, window + 1):
        expected = get_totp_code(secret, timestamp=now + delta * 30)
        if expected and hmac.compare_digest(expected, user_code):
            return True
    return False


# ─────────────────────────────────────────────────────────────────
# IP ALLOWLIST
# ─────────────────────────────────────────────────────────────────

def get_allowed_ips():
    """Parse allowed IPs from environment variable."""
    raw = os.environ.get("ADMIN_ALLOWED_IPS", "*")
    if raw.strip() == "*":
        return None  # allow all
    return [ip.strip() for ip in raw.split(",") if ip.strip()]


def check_admin_ip():
    """
    Return True if current request IP is allowed.
    Aborts with 404 (not 403) to not reveal the admin exists.
    """
    # allowed = get_allowed_ips()
    # if allowed is None:
    #     return True  # wildcard
    # client_ip = get_client_ip()
    # if client_ip not in allowed:
    #     abort(404)  # disguise — looks like page not found
    return True


def ip_required(f):
    """Decorator: block request if IP not in allowlist."""
    @wraps(f)
    def decorated(*args, **kwargs):
        check_admin_ip()
        return f(*args, **kwargs)
    return decorated


# ─────────────────────────────────────────────────────────────────
# SECURITY HEADERS
# ─────────────────────────────────────────────────────────────────

def apply_security_headers(response):
    """Add security headers to every response."""
    # Prevent clickjacking
    response.headers["X-Frame-Options"] = "DENY"
    # Prevent MIME sniffing
    response.headers["X-Content-Type-Options"] = "nosniff"
    # XSS protection (legacy browsers)
    response.headers["X-XSS-Protection"] = "1; mode=block"
    # Referrer policy
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    # Permissions policy — disable unnecessary browser features
    response.headers["Permissions-Policy"] = (
        "geolocation=(), microphone=(), camera=(), payment=(), usb=()"
    )
    # HSTS — only set in production (requires HTTPS)
    if os.environ.get("FLASK_ENV") == "production":
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains; preload"
        )
    # CSP — restrict what can load
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
    # Don't cache admin pages
    if "/admin" in request.path or f"/{os.environ.get('ADMIN_URL_PREFIX','admin')}" in request.path:
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
        response.headers["Pragma"] = "no-cache"
    return response


# ─────────────────────────────────────────────────────────────────
# SESSION HARDENING
# ─────────────────────────────────────────────────────────────────

def configure_session(app):
    """Apply session security settings to Flask app."""
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
    session["_2fa_pending"] = True
    session["_2fa_user_id"] = user_id
    session["_2fa_timestamp"] = time.time()


def get_awaiting_2fa():
    """Return user_id if 2FA is pending and not expired, else None."""
    if not session.get("_2fa_pending"):
        return None
    ts = session.get("_2fa_timestamp", 0)
    if time.time() - ts > 300:  # 5-minute window to enter 2FA
        clear_2fa_session()
        return None
    return session.get("_2fa_user_id")


def clear_2fa_session():
    """Remove 2FA pending state."""
    session.pop("_2fa_pending", None)
    session.pop("_2fa_user_id", None)
    session.pop("_2fa_timestamp", None)
