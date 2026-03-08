#!/usr/bin/env python3
"""
setup_2fa.py — Run this ONCE to set up Google Authenticator / Authy.

Usage:
    python setup_2fa.py

This will:
1. Generate a secure TOTP secret
2. Show a QR code URL (scan with Google Authenticator)
3. Print the secret to paste into your .env file
4. Ask you to verify a code before saving
"""

import base64
import hashlib
import hmac
import os
import struct
import time
import urllib.parse


def generate_totp_secret(length=20):
    """Generate a secure base32-encoded TOTP secret."""
    random_bytes = os.urandom(length)
    # Base32 encode without padding issues
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    result = ""
    buffer = 0
    bits_left = 0
    for byte in random_bytes:
        buffer = (buffer << 8) | byte
        bits_left += 8
        while bits_left >= 5:
            bits_left -= 5
            result += alphabet[(buffer >> bits_left) & 0x1F]
    if bits_left > 0:
        result += alphabet[(buffer << (5 - bits_left)) & 0x1F]
    return result


def base32_decode(s):
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


def get_totp(secret, time_step=30, digits=6):
    """Generate current TOTP code."""
    key = base32_decode(secret)
    counter = int(time.time() // time_step)
    msg = struct.pack(">Q", counter)
    h = hmac.new(key, msg, hashlib.sha1).digest()
    offset = h[-1] & 0x0F
    code = struct.unpack(">I", h[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(code % (10 ** digits)).zfill(digits)


def get_totp_uri(secret, username, issuer="PortfolioAdmin"):
    """Generate otpauth:// URI for QR code."""
    params = urllib.parse.urlencode({
        "secret": secret,
        "issuer": issuer,
        "algorithm": "SHA1",
        "digits": "6",
        "period": "30",
    })
    label = urllib.parse.quote(f"{issuer}:{username}")
    return f"otpauth://totp/{label}?{params}"


def get_qr_url(totp_uri):
    """Generate a QR code URL using Google Charts API."""
    encoded = urllib.parse.quote(totp_uri)
    return f"https://api.qrserver.com/v1/create-qr-code/?size=250x250&data={encoded}"


def update_env_file(secret):
    """Update TOTP_SECRET in .env file."""
    env_path = os.path.join(os.path.dirname(__file__), ".env")
    if not os.path.exists(env_path):
        print("⚠️  .env file not found — cannot auto-update.")
        return False
    with open(env_path, "r") as f:
        content = f.read()
    if "TOTP_SECRET=" in content:
        lines = content.splitlines()
        updated = []
        for line in lines:
            if line.startswith("TOTP_SECRET="):
                updated.append(f"TOTP_SECRET={secret}")
            else:
                updated.append(line)
        content = "\n".join(updated) + "\n"
    else:
        content += f"\nTOTP_SECRET={secret}\n"
    with open(env_path, "w") as f:
        f.write(content)
    return True


def main():
    print()
    print("=" * 56)
    print("  Portfolio Admin — 2FA Setup")
    print("=" * 56)
    print()

    # Load existing username from .env if available
    admin_username = "admin"
    env_path = os.path.join(os.path.dirname(__file__), ".env")
    if os.path.exists(env_path):
        with open(env_path) as f:
            for line in f:
                if line.startswith("ADMIN_USERNAME="):
                    admin_username = line.split("=", 1)[1].strip()
                elif line.startswith("TOTP_SECRET=") and "=" in line:
                    existing = line.split("=", 1)[1].strip()
                    if existing:
                        print(f"⚠️  A TOTP secret already exists in .env.")
                        choice = input("   Generate a new one? (y/N): ").strip().lower()
                        if choice != "y":
                            print("Aborted. Existing secret kept.")
                            return

    # Generate secret
    secret = generate_totp_secret()
    totp_uri = get_totp_uri(secret, admin_username)
    qr_url = get_qr_url(totp_uri)

    print(f"✅ TOTP Secret generated for user: {admin_username}")
    print()
    print("-" * 56)
    print("  STEP 1 — Scan this QR code with Google Authenticator")
    print("           or Authy on your phone:")
    print("-" * 56)
    print()
    print(f"  QR Code URL (open in browser to scan):")
    print(f"  {qr_url}")
    print()
    print("-" * 56)
    print("  STEP 2 — Or manually enter this secret key in your app:")
    print("-" * 56)
    print()
    print(f"  Secret:  {secret}")
    print()
    print("-" * 56)
    print("  STEP 3 — Verify it works. Enter the 6-digit code")
    print("           shown in your authenticator app:")
    print("-" * 56)
    print()

    attempts = 3
    verified = False
    while attempts > 0:
        code = input(f"  Enter code ({attempts} attempt{'s' if attempts>1 else ''} left): ").strip()
        expected = get_totp(secret)
        # Also check previous/next window (30s drift tolerance)
        key = base32_decode(secret)
        window_ok = False
        for delta in [-1, 0, 1]:
            counter = int(time.time() // 30) + delta
            msg = struct.pack(">Q", counter)
            h = hmac.new(key, msg, hashlib.sha1).digest()
            offset = h[-1] & 0x0F
            c = str(struct.unpack(">I", h[offset:offset+4])[0] & 0x7FFFFFFF % 1000000).zfill(6)
            if code == c or code == expected:
                window_ok = True
                break
        if window_ok:
            verified = True
            break
        attempts -= 1
        if attempts > 0:
            print(f"  ❌ Wrong code. Try again.")

    if not verified:
        print()
        print("  ❌ Verification failed. Secret NOT saved.")
        print("     Run this script again and scan the QR code fresh.")
        return

    print()
    print("  ✅ Code verified!")
    print()
    print("-" * 56)
    print("  STEP 4 — Saving secret to .env")
    print("-" * 56)

    if update_env_file(secret):
        print()
        print("  ✅ TOTP_SECRET saved to .env")
    else:
        print()
        print(f"  ⚠️  Could not auto-save. Add this to your .env manually:")
        print(f"  TOTP_SECRET={secret}")

    print()
    print("=" * 56)
    print("  2FA setup complete!")
    print("  Next time you log into /admin, you'll need your")
    print("  authenticator app in addition to your password.")
    print("=" * 56)
    print()


if __name__ == "__main__":
    main()
