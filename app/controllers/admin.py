import os
import re
from flask import (Blueprint, render_template, redirect, url_for,
                   request, flash, jsonify, abort, session)
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import check_password_hash, generate_password_hash
from app import db
from app.models.user import User
from app.models.content import Project, Video
from app.security import (
    check_admin_ip, get_client_ip,
    is_ip_locked, record_failed_login, clear_failed_attempts, lockout_remaining,
    verify_totp, set_awaiting_2fa, get_awaiting_2fa, clear_2fa_session,
)

admin_bp = Blueprint("admin", __name__)


# ── IP guard on EVERY admin request ──────────────────────────────
@admin_bp.before_request
def enforce_ip_allowlist():
    check_admin_ip()


# ─────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────

def slugify(text):
    text = text.lower().strip()
    text = re.sub(r"[^\w\s-]", "", text)
    text = re.sub(r"[\s_-]+", "-", text)
    return text.strip("-")


def extract_video_id(url, platform):
    if not url:
        return None
    if platform == "youtube":
        m = re.search(r"(?:v=|youtu\.be/|embed/)([A-Za-z0-9_-]{11})", url)
        if m:
            return m.group(1)
    if platform == "vimeo":
        m = re.search(r"vimeo\.com/(?:video/)?(\d+)", url)
        if m:
            return m.group(1)
    return None


def detect_platform(url):
    if not url:
        return "other"
    if "youtube.com" in url or "youtu.be" in url:
        return "youtube"
    if "vimeo.com" in url:
        return "vimeo"
    if "instagram.com" in url:
        return "instagram"
    return "other"


def totp_is_enabled():
    secret = os.environ.get("TOTP_SECRET", "").strip()
    enabled = os.environ.get("TOTP_ENABLED", "true").lower() == "true"
    return enabled and bool(secret)


# ─────────────────────────────────────────────────────────────────
# STEP 1 — PASSWORD LOGIN
# ─────────────────────────────────────────────────────────────────

@admin_bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("admin.dashboard"))

    ip = get_client_ip()

    # IP lockout check
    if is_ip_locked(ip):
        remaining = lockout_remaining(ip)
        mins = remaining // 60
        secs = remaining % 60
        return render_template("admin/login.html",
            error=f"Too many failed attempts. Locked for {mins}m {secs}s.",
            locked=True)

    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password_hash, password):
            clear_failed_attempts(ip)

            if totp_is_enabled():
                # Park credentials, redirect to 2FA step
                set_awaiting_2fa(user.id)
                return redirect(url_for("admin.verify_2fa"))
            else:
                # No 2FA — log in directly
                login_user(user, remember=False)
                user.record_login(ip)
                db.session.commit()
                return redirect(url_for("admin.dashboard"))
        else:
            locked = record_failed_login(ip)
            if locked:
                remaining = lockout_remaining(ip)
                error = f"Too many failed attempts. Locked for {remaining // 60}m {remaining % 60}s."
            else:
                # Generic message — don't reveal which field was wrong
                error = "Invalid credentials."

    return render_template("admin/login.html", error=error, locked=False)


# ─────────────────────────────────────────────────────────────────
# STEP 2 — TOTP VERIFICATION
# ─────────────────────────────────────────────────────────────────

@admin_bp.route("/verify", methods=["GET", "POST"])
def verify_2fa():
    user_id = get_awaiting_2fa()
    if not user_id:
        return redirect(url_for("admin.login"))

    ip = get_client_ip()
    if is_ip_locked(ip):
        clear_2fa_session()
        return redirect(url_for("admin.login"))

    error = None
    if request.method == "POST":
        code = request.form.get("code", "").strip().replace(" ", "")
        totp_secret = os.environ.get("TOTP_SECRET", "")

        if verify_totp(totp_secret, code):
            user = User.query.get(user_id)
            if not user:
                clear_2fa_session()
                return redirect(url_for("admin.login"))
            clear_2fa_session()
            clear_failed_attempts(ip)
            login_user(user, remember=False)
            user.record_login(ip)
            db.session.commit()
            return redirect(url_for("admin.dashboard"))
        else:
            locked = record_failed_login(ip)
            if locked:
                clear_2fa_session()
                return redirect(url_for("admin.login"))
            error = "Invalid code. Check your authenticator app."

    return render_template("admin/verify_2fa.html", error=error)


# ─────────────────────────────────────────────────────────────────
# LOGOUT
# ─────────────────────────────────────────────────────────────────

@admin_bp.route("/logout")
@login_required
def logout():
    logout_user()
    session.clear()
    return redirect(url_for("public.index"))


# ─────────────────────────────────────────────────────────────────
# DASHBOARD
# ─────────────────────────────────────────────────────────────────

@admin_bp.route("/")
@login_required
def dashboard():
    return render_template("admin/dashboard.html",
        total_projects=Project.query.count(),
        total_videos=Video.query.count(),
        recent_projects=Project.query.order_by(Project.created_at.desc()).limit(5).all(),
        recent_videos=Video.query.order_by(Video.created_at.desc()).limit(5).all(),
        totp_active=totp_is_enabled(),
        client_ip=get_client_ip(),
    )


# ─────────────────────────────────────────────────────────────────
# PROJECTS CRUD
# ─────────────────────────────────────────────────────────────────

@admin_bp.route("/projects")
@login_required
def projects():
    all_projects = Project.query.order_by(Project.order, Project.created_at.desc()).all()
    return render_template("admin/projects.html", projects=all_projects)


@admin_bp.route("/projects/new", methods=["GET", "POST"])
@login_required
def project_new():
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        slug = slugify(request.form.get("slug", "") or title)
        base = slug; i = 1
        while Project.query.filter_by(slug=slug).first():
            slug = f"{base}-{i}"; i += 1

        project = Project(
            title=title, slug=slug,
            description=request.form.get("description", ""),
            short_desc=request.form.get("short_desc", ""),
            category=request.form.get("category", "web"),
            tech_stack=request.form.get("tech_stack", ""),
            thumbnail_url=request.form.get("thumbnail_url", ""),
            live_url=request.form.get("live_url", ""),
            github_url=request.form.get("github_url", ""),
            featured=bool(request.form.get("featured")),
            order=int(request.form.get("order", 0) or 0),
            published=bool(request.form.get("published")),
        )
        db.session.add(project)
        db.session.commit()
        flash("Project created!", "success")
        return redirect(url_for("admin.projects"))
    return render_template("admin/project_form.html", project=None, action="new")


@admin_bp.route("/projects/<int:pid>/edit", methods=["GET", "POST"])
@login_required
def project_edit(pid):
    project = Project.query.get_or_404(pid)
    if request.method == "POST":
        project.title = request.form.get("title", "").strip()
        if request.form.get("slug"):
            project.slug = slugify(request.form.get("slug"))
        project.description = request.form.get("description", "")
        project.short_desc = request.form.get("short_desc", "")
        project.category = request.form.get("category", "web")
        project.tech_stack = request.form.get("tech_stack", "")
        project.thumbnail_url = request.form.get("thumbnail_url", "")
        project.live_url = request.form.get("live_url", "")
        project.github_url = request.form.get("github_url", "")
        project.featured = bool(request.form.get("featured"))
        project.order = int(request.form.get("order", 0) or 0)
        project.published = bool(request.form.get("published"))
        db.session.commit()
        flash("Project updated!", "success")
        return redirect(url_for("admin.projects"))
    return render_template("admin/project_form.html", project=project, action="edit")


@admin_bp.route("/projects/<int:pid>/delete", methods=["POST"])
@login_required
def project_delete(pid):
    project = Project.query.get_or_404(pid)
    db.session.delete(project)
    db.session.commit()
    flash("Project deleted.", "info")
    return redirect(url_for("admin.projects"))


@admin_bp.route("/projects/<int:pid>/toggle", methods=["POST"])
@login_required
def project_toggle(pid):
    project = Project.query.get_or_404(pid)
    project.published = not project.published
    db.session.commit()
    return jsonify({"published": project.published})


# ─────────────────────────────────────────────────────────────────
# VIDEOS CRUD
# ─────────────────────────────────────────────────────────────────

@admin_bp.route("/videos")
@login_required
def videos():
    all_videos = Video.query.order_by(Video.order, Video.created_at.desc()).all()
    return render_template("admin/videos.html", videos=all_videos)


@admin_bp.route("/videos/new", methods=["GET", "POST"])
@login_required
def video_new():
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        slug = slugify(request.form.get("slug", "") or title)
        base = slug; i = 1
        while Video.query.filter_by(slug=slug).first():
            slug = f"{base}-{i}"; i += 1

        raw_url = request.form.get("video_url", "").strip()
        platform = request.form.get("platform") or detect_platform(raw_url)

        video = Video(
            title=title, slug=slug,
            description=request.form.get("description", ""),
            short_desc=request.form.get("short_desc", ""),
            category=request.form.get("category", "reel"),
            platform=platform, video_url=raw_url,
            embed_id=extract_video_id(raw_url, platform),
            thumbnail_url=request.form.get("thumbnail_url", ""),
            duration=request.form.get("duration", ""),
            tools_used=request.form.get("tools_used", ""),
            featured=bool(request.form.get("featured")),
            order=int(request.form.get("order", 0) or 0),
            published=bool(request.form.get("published")),
        )
        db.session.add(video)
        db.session.commit()
        flash("Video added!", "success")
        return redirect(url_for("admin.videos"))
    return render_template("admin/video_form.html", video=None, action="new")


@admin_bp.route("/videos/<int:vid>/edit", methods=["GET", "POST"])
@login_required
def video_edit(vid):
    video = Video.query.get_or_404(vid)
    if request.method == "POST":
        video.title = request.form.get("title", "").strip()
        if request.form.get("slug"):
            video.slug = slugify(request.form.get("slug"))
        video.description = request.form.get("description", "")
        video.short_desc = request.form.get("short_desc", "")
        video.category = request.form.get("category", "reel")
        raw_url = request.form.get("video_url", "").strip()
        video.video_url = raw_url
        platform = request.form.get("platform") or detect_platform(raw_url)
        video.platform = platform
        video.embed_id = extract_video_id(raw_url, platform)
        video.thumbnail_url = request.form.get("thumbnail_url", "")
        video.duration = request.form.get("duration", "")
        video.tools_used = request.form.get("tools_used", "")
        video.featured = bool(request.form.get("featured"))
        video.order = int(request.form.get("order", 0) or 0)
        video.published = bool(request.form.get("published"))
        db.session.commit()
        flash("Video updated!", "success")
        return redirect(url_for("admin.videos"))
    return render_template("admin/video_form.html", video=video, action="edit")


@admin_bp.route("/videos/<int:vid>/delete", methods=["POST"])
@login_required
def video_delete(vid):
    video = Video.query.get_or_404(vid)
    db.session.delete(video)
    db.session.commit()
    flash("Video deleted.", "info")
    return redirect(url_for("admin.videos"))


@admin_bp.route("/videos/<int:vid>/toggle", methods=["POST"])
@login_required
def video_toggle(vid):
    video = Video.query.get_or_404(vid)
    video.published = not video.published
    db.session.commit()
    return jsonify({"published": video.published})


# ─────────────────────────────────────────────────────────────────
# SETTINGS
# ─────────────────────────────────────────────────────────────────

@admin_bp.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    error = None
    if request.method == "POST":
        current_pw = request.form.get("current_password", "")
        new_pw = request.form.get("new_password", "")
        confirm_pw = request.form.get("confirm_password", "")
        if not check_password_hash(current_user.password_hash, current_pw):
            error = "Current password is incorrect."
        elif len(new_pw) < 8:
            error = "New password must be at least 8 characters."
        elif new_pw != confirm_pw:
            error = "Passwords do not match."
        else:
            current_user.password_hash = generate_password_hash(
                new_pw, method="pbkdf2:sha256:600000"
            )
            db.session.commit()
            flash("Password changed successfully!", "success")
            return redirect(url_for("admin.dashboard"))
    return render_template("admin/settings.html",
        error=error,
        totp_active=totp_is_enabled(),
        last_login=current_user.last_login_at,
        last_ip=current_user.last_login_ip,
        login_count=current_user.login_count,
    )
