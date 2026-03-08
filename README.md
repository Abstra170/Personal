# Alex Morgan - Portfolio (Flask MVC)

A full-stack portfolio website built with Flask. Includes a public-facing site
with projects and videos, and a private admin panel to manage all content.

---

## Table of Contents

1. Project Structure
2. Quick Start (First Time)
3. Configuration (.env)
4. Security Setup
5. Admin Panel Guide
6. Public Website Pages
7. Database & Models
8. Customizing the Site
9. Common Tasks
10. Deploying to Production
11. Troubleshooting

---

## 1. Project Structure

    portfolio/
    |
    |-- run.py                    <-- START HERE: launches the Flask app
    |-- setup_2fa.py              <-- Run once to set up Google Authenticator
    |-- requirements.txt          <-- Python packages to install
    |-- .env                      <-- Your private config (NEVER commit to git)
    |-- .env.example              <-- Template for .env (safe to commit)
    |-- .gitignore                <-- Files git should ignore
    |-- README.md                 <-- This file
    |
    |-- app/
        |-- __init__.py           <-- App factory: creates and wires up Flask
        |-- security.py           <-- All security logic (IP check, 2FA, lockout)
        |
        |-- models/
        |   |-- user.py           <-- Admin user (login, password, audit trail)
        |   |-- content.py        <-- Project and Video database models
        |
        |-- controllers/
        |   |-- public.py         <-- Public routes (homepage, projects, videos)
        |   |-- admin.py          <-- Admin routes (login, CRUD for content)
        |
        |-- views/
            |-- templates/
                |-- base.html           <-- Shared layout (nav, footer, modal)
                |-- index.html          <-- Homepage
                |-- projects.html       <-- All projects page
                |-- project_detail.html <-- Single project page
                |-- videos.html         <-- All videos page
                |-- video_detail.html   <-- Single video page
                |-- about.html          <-- About me page
                |-- contact.html        <-- Contact form page
                |
                |-- admin/
                    |-- base_admin.html   <-- Admin panel layout (sidebar)
                    |-- login.html        <-- Login (Step 1: password)
                    |-- verify_2fa.html   <-- Login (Step 2: 2FA code)
                    |-- dashboard.html    <-- Admin home with stats
                    |-- projects.html     <-- List and manage projects
                    |-- project_form.html <-- Add or edit a project
                    |-- videos.html       <-- List and manage videos
                    |-- video_form.html   <-- Add or edit a video
                    |-- settings.html     <-- Password, security info

---

## 2. Quick Start (First Time)

    Step 1 - Install dependencies
    cd portfolio
    pip install -r requirements.txt

    Step 2 - Configure .env (open the .env file and change these):
    SECRET_KEY=      <- generate: python -c "import secrets; print(secrets.token_hex(48))"
    ADMIN_PASSWORD=  <- choose a strong password
    ADMIN_URL_PREFIX=<- your secret admin URL slug (e.g. my-private-panel-8x2k)

    Step 3 - Set up 2FA (recommended)
    python setup_2fa.py
    (scan QR code with Google Authenticator or Authy on your phone)

    Step 4 - Run
    python run.py

    Website: http://localhost:5000
    Admin:   http://localhost:5000/YOUR_ADMIN_URL_PREFIX/login

On first run the admin user is created automatically from your .env credentials.

---

## 3. Configuration (.env)

Every setting lives in the .env file. Never commit it to git.

SECRET_KEY
  A long random string Flask uses to encrypt sessions and CSRF tokens.
  If this changes, all existing sessions are invalidated (everyone logged out).
  Generate: python -c "import secrets; print(secrets.token_hex(48))"

FLASK_ENV
  development = debug mode, auto-reload on code changes, detailed errors.
  production  = no debug, optimised for live servers. ALWAYS use in production.

DATABASE_URL
  Where the database lives. Default: sqlite:///portfolio.db (instance/ folder).
  For PostgreSQL: postgresql://username:password@localhost/portfolio_db

ADMIN_USERNAME / ADMIN_PASSWORD
  Credentials for admin panel. Set BEFORE the first run.
  After first run, change password via Admin > Settings.

ADMIN_ALLOWED_IPS
  Only these IPs can see the admin panel. Everyone else gets 404.
  Find your IP: https://whatismyip.com
  Multiple IPs: comma-separated  e.g. 203.0.113.42,198.51.100.7
  Local dev:    127.0.0.1,::1
  Disable:      *  (not recommended)

  NOTE: Most home internet IPs change every few days. If you suddenly
  cannot access admin, update this line in .env and restart.

ADMIN_URL_PREFIX
  Admin lives at this URL instead of /admin.
  Example: my-secret-panel-x7k2m  ->  yoursite.com/my-secret-panel-x7k2m/login
  Choose something long and random. Only you should know it.

TOTP_ENABLED / TOTP_SECRET
  Two-factor authentication. After running setup_2fa.py, TOTP_SECRET is
  filled automatically. Set TOTP_ENABLED=false to disable (not recommended).

MAX_LOGIN_ATTEMPTS / LOGIN_LOCKOUT_SECONDS
  After MAX_LOGIN_ATTEMPTS failed logins from one IP, that IP is blocked for
  LOGIN_LOCKOUT_SECONDS. Default: 5 attempts, 900 seconds (15 minutes).

SESSION_LIFETIME_SECONDS
  How long you stay logged in. Default: 3600 (1 hour).

SESSION_COOKIE_SECURE
  Set true on a live HTTPS server. Keep false for local development.

CSP_ENABLED
  Content Security Policy headers. Prevents XSS attacks. Keep true.

---

## 4. Security Setup

The admin panel has 4 layers of protection you have to beat simultaneously:

    Layer 1 -- Hidden URL
      /admin does not exist. Only your secret ADMIN_URL_PREFIX works.
      Anyone guessing /admin gets a 404.

    Layer 2 -- IP Allowlist
      Even if someone knows your secret URL, unlisted IPs get 404.
      The 404 (not 403) means it still looks like the page does not exist.

    Layer 3 -- Password + Brute-force Lockout
      Username + password. 5 wrong attempts = 15 minute IP lockout.

    Layer 4 -- Two-Factor Auth (TOTP)
      6-digit code from your phone app, changes every 30 seconds.
      Even with the correct password, you cannot log in without the code.

Setting up 2FA:
  Run: python setup_2fa.py
  It generates a QR code URL, you scan it with your authenticator app,
  verify a code, and the secret is saved to .env automatically.

  Compatible apps: Google Authenticator, Authy, 1Password, Bitwarden,
                   Microsoft Authenticator

Changing your password:
  Log into admin > Settings > Change Password

If you get locked out (IP changed):
  1. Open .env
  2. Add your new IP to ADMIN_ALLOWED_IPS
  3. Restart the server

If you forget your password:
  Run this from the portfolio/ folder:
    python -c "
    from app import create_app, db
    from app.models.user import User
    from werkzeug.security import generate_password_hash
    app = create_app()
    with app.app_context():
        u = User.query.first()
        u.password_hash = generate_password_hash('NewPassword123!')
        db.session.commit()
        print('Password reset!')
    "

---

## 5. Admin Panel Guide

Access: http://localhost:5000/YOUR_ADMIN_PREFIX/login

Dashboard
  Shows total projects, total videos, recent additions.
  Security status bar at bottom: 2FA active status, your current IP.

Managing Projects

  Add:
    Admin > Projects > New Project
    Fill Title, Description, Category, Tech Stack (comma-separated)
    Paste a Thumbnail URL (from Unsplash, Cloudinary, or any image host)
    Live URL = your deployed site, GitHub URL = repo link
    Published ON = visible on public site
    Featured ON  = appears in homepage bento grid

  Edit: click Edit next to any project in the list
  Delete: click Delete (asks for confirmation)
  Toggle: click the toggle to publish/unpublish without opening edit form
  Order: lower number = appears first. Set 0 for your best work.
  Categories: web, mobile, design, other

Managing Videos

  Same as projects plus:
  Video URL: paste YouTube or Vimeo URL - embed ID extracted automatically
  Platform:  auto-detected from URL (YouTube / Vimeo / Instagram / Other)
  Duration:  display text like "2:34" or "90 sec"
  Tools Used: comma-separated e.g. "Premiere Pro, After Effects, DaVinci"

  YouTube thumbnail URL format:
    https://img.youtube.com/vi/YOUR_VIDEO_ID/maxresdefault.jpg

Settings
  Change admin password
  View 2FA status
  View login history (last time, IP, total count)
  Instructions for IP allowlist and 2FA management

---

## 6. Public Website Pages

  URL                  Template              Description
  /                    index.html            Homepage: hero, projects, videos
  /projects            projects.html         All published projects, filterable
  /projects/<slug>     project_detail.html   Single project, tech stack, links
  /videos              videos.html           All videos with YouTube modal
  /videos/<slug>       video_detail.html     Single video with embed player
  /about               about.html            About me
  /contact             contact.html          Contact form (frontend only)

All pages share base.html which contains:
  - Navigation bar with dark/light theme toggle
  - Aurora blob background with mouse parallax
  - YouTube video modal (Watch Reel button + video cards)
  - Full footer with links and social icons
  - Scroll-reveal animations on all sections

---

## 7. Database & Models

Database is SQLite by default: instance/portfolio.db
Created automatically on first run. No setup required.

Project fields:
  title         - Project name
  slug          - URL slug (auto-generated from title)
  description   - Full description (detail page)
  short_desc    - Short blurb (cards and listings)
  category      - web / mobile / design / other
  tech_stack    - Comma-separated: "React, Node.js, PostgreSQL"
  thumbnail_url - Cover image URL
  live_url      - Deployed project URL
  github_url    - GitHub repository URL
  featured      - Show on homepage bento grid (true/false)
  order         - Sort order (0 = first)
  published     - Visible on public site (true/false)
  created_at    - Auto-set on creation
  updated_at    - Auto-updated on save

Video fields:
  title         - Video title
  slug          - URL slug (auto-generated)
  description   - Full description
  short_desc    - Short blurb
  category      - reel / cinematic / tutorial / commercial / other
  platform      - youtube / vimeo / instagram / other
  video_url     - Original URL you pasted
  embed_id      - Extracted ID (e.g. dQw4w9WgXcQ for YouTube)
  thumbnail_url - Cover image URL
  duration      - Display text e.g. "2:34"
  tools_used    - Comma-separated e.g. "Premiere Pro, DaVinci"
  featured      - Show on homepage
  order         - Sort order
  published     - Visible publicly

User fields:
  username      - Login username
  password_hash - Hashed with pbkdf2:sha256 (600,000 rounds)
  last_login_at - Timestamp of last successful login
  last_login_ip - IP of last login
  login_count   - Total successful logins

---

## 8. Customizing the Site

Change Your Name
  Find and replace "Alex Morgan" in:
    app/views/templates/base.html          (nav logo, footer)
    app/views/templates/index.html         (hero, page title)
    app/views/templates/about.html         (all text)
    app/views/templates/admin/login.html   (logo)

Change the Hero Background Video
  In index.html, find the .hero-vid section.
  Replace the comment block with a real iframe:

    <iframe
      src="https://www.youtube.com/embed/YOUR_VIDEO_ID?autoplay=1&mute=1&loop=1&playlist=YOUR_VIDEO_ID&controls=0"
      allow="autoplay;encrypted-media" allowfullscreen>
    </iframe>

  Your video must have "Allow embedding" enabled in YouTube Studio.
  (YouTube Studio > Video > Edit > More options > Allow embedding)

  If you do not have a background video, the animated gradient fallback
  already looks good on its own. Just leave the iframe out.

Change the "Watch Reel" Modal Video
  In index.html, find:
    onclick="openVideo('https://www.youtube.com/embed/dQw4w9WgXcQ?autoplay=1&rel=0')"
  Replace dQw4w9WgXcQ with your YouTube showreel video ID.

Change Colors
  All colors are CSS variables in base.html inside the :root block:
    --c:  #0a84ff   Primary blue (links, buttons, accents)
    --c2: #ff375f   Red/pink (secondary accent, delete buttons)
    --c3: #bf5af2   Purple (gradients, hero text)
    --g:  #32d74b   Green (live/available indicator)

Update Social Links in Footer
  In base.html, find the .ft-socials section.
  Replace href="#" with your real URLs:
    GitHub:   https://github.com/yourusername
    LinkedIn: https://linkedin.com/in/yourusername
    Twitter:  https://twitter.com/yourusername
    YouTube:  https://youtube.com/@yourchannel

Add Contact Form Email Sending
  The contact form is frontend-only. To send real emails, install Flask-Mail:
    pip install Flask-Mail
  Then add email handling in controllers/public.py in the contact() route.

---

## 9. Common Tasks

Adding a project
  Admin > Projects > New Project > fill form > Published ON

Adding a video
  Admin > Videos > New Video > paste YouTube/Vimeo URL > Published ON
  Thumbnail: https://img.youtube.com/vi/YOUR_VIDEO_ID/maxresdefault.jpg

Backing up your content
  Copy instance/portfolio.db to a safe location.
  That single file contains everything.

Restoring from backup
  Replace instance/portfolio.db with your backup file, restart.

Reset database (start fresh)
  Delete instance/portfolio.db and restart. All content is deleted.

Change admin password via command line (if locked out of Settings)
  See "If you forget your password" in section 4.

---

## 10. Deploying to Production

Update .env for production:
  FLASK_ENV=production
  SESSION_COOKIE_SECURE=true
  ADMIN_ALLOWED_IPS=your.real.public.ip

Install Gunicorn:
  pip install gunicorn

Run:
  gunicorn -w 4 -b 0.0.0.0:8000 "run:app"

Nginx config (put in /etc/nginx/sites-available/portfolio):
  server {
      listen 80;
      server_name yourdomain.com;
      return 301 https://$server_name$request_uri;
  }
  server {
      listen 443 ssl;
      server_name yourdomain.com;
      ssl_certificate /etc/letsencrypt/live/yourdomain.com/fullchain.pem;
      ssl_certificate_key /etc/letsencrypt/live/yourdomain.com/privkey.pem;
      location / {
          proxy_pass http://127.0.0.1:8000;
          proxy_set_header Host $host;
          proxy_set_header X-Real-IP $remote_addr;
          proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
      }
  }

Free SSL:
  sudo apt install certbot python3-certbot-nginx
  sudo certbot --nginx -d yourdomain.com

Free Hosting Options:
  Railway (easiest): push to GitHub, connect repo, add env vars, deploy
  Render: New Web Service, build: pip install -r requirements.txt,
          start: gunicorn run:app, add env vars in dashboard
  VPS (DigitalOcean/Linode): full control, use Nginx + Gunicorn above

---

## 11. Troubleshooting

UnicodeDecodeError on startup
  Your .env has special characters. Open it in a text editor, delete all
  comment lines (lines starting with #), save, restart.

"No such table" error
  Delete instance/portfolio.db and restart. DB will be recreated.

Cannot access admin panel (404)
  - Check ADMIN_URL_PREFIX in .env matches the URL you are visiting
  - Check your IP is in ADMIN_ALLOWED_IPS (visit whatismyip.com)
  - Restart the server after any .env change

Admin locked out after failed logins
  Wait 15 minutes, OR restart the server (lockout is in-memory, resets on restart).

Hero video shows "Video unavailable"
  The placeholder video ID is invalid. Add your own YouTube video ID.
  See "Change the Hero Background Video" in section 8.
  Or remove the iframe entirely to use the animated gradient background.

"Watch Reel" does not play a video
  Replace the placeholder YouTube ID in index.html with your showreel ID.
  See "Change the Watch Reel Modal Video" in section 8.

2FA code not accepted
  - Check your phone clock is accurate (Settings > Date & Time > Automatic)
  - Each code is valid for 30 seconds, try entering it immediately after it refreshes
  - If still failing, re-run: python setup_2fa.py

Secret key warning on every restart
  Set a fixed SECRET_KEY in .env. Without it, a new key is generated each
  restart which invalidates all sessions.
