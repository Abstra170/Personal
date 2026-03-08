import os
from flask import Blueprint, render_template, abort,request,flash,redirect,url_for
from app.models.content import Project, Video
from flask_mail import Message
from ..extensions import mail

public_bp = Blueprint("public", __name__)


@public_bp.route("/")
def index():
    featured_projects = Project.query.filter_by(published=True, featured=True).order_by(Project.order).all()
    featured_videos = Video.query.filter_by(published=True, featured=True).order_by(Video.order).all()
    # Fallback: grab latest if no featured set
    if not featured_projects:
        featured_projects = Project.query.filter_by(published=True).order_by(Project.order, Project.created_at.desc()).limit(6).all()
    if not featured_videos:
        featured_videos = Video.query.filter_by(published=True).order_by(Video.order, Video.created_at.desc()).limit(3).all()
    return render_template("index.html", projects=featured_projects, videos=featured_videos)


@public_bp.route("/projects")
def projects():
    all_projects = Project.query.filter_by(published=True).order_by(Project.order, Project.created_at.desc()).all()
    categories = sorted(set(p.category for p in all_projects))
    return render_template("projects.html", projects=all_projects, categories=categories)


@public_bp.route("/projects/<slug>")
def project_detail(slug):
    project = Project.query.filter_by(slug=slug, published=True).first_or_404()
    related = Project.query.filter(
        Project.category == project.category,
        Project.id != project.id,
        Project.published == True
    ).limit(3).all()
    return render_template("project_detail.html", project=project, related=related)


@public_bp.route("/videos")
def videos():
    all_videos = Video.query.filter_by(published=True).order_by(Video.order, Video.created_at.desc()).all()
    categories = sorted(set(v.category for v in all_videos))
    return render_template("videos.html", videos=all_videos, categories=categories)


@public_bp.route("/videos/<slug>")
def video_detail(slug):
    video = Video.query.filter_by(slug=slug, published=True).first_or_404()
    related = Video.query.filter(
        Video.category == video.category,
        Video.id != video.id,
        Video.published == True
    ).limit(3).all()
    return render_template("video_detail.html", video=video, related=related)


@public_bp.route("/about")
def about():
    return render_template("about.html")



@public_bp.route("/contact", methods=["GET", "POST"])
def contact():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip()
        project_type = request.form.get("project_type", "").strip()
        message_text = request.form.get("message", "").strip()

        if not name or not email or not message_text:
            flash("Please fill all required fields.", "danger")
            return redirect(url_for("public.contact"))

        receiver = os.getenv("CONTACT_RECEIVER")

        msg = Message(
            subject=f"New Contact Form Message from {name}",
            recipients=[receiver]
        )

        msg.body = f"""
You received a new message from your portfolio contact form.

Name: {name}
Email: {email}
Project Type: {project_type}

Message:
{message_text}
"""

        try:
            mail.send(msg)
            flash("Your message has been sent successfully!", "success")
        except Exception as e:
            print("Mail error:", e)
            flash("Message could not be sent. Please try again later.", "danger")

        return redirect(url_for("public.contact"))

    return render_template("contact.html")
