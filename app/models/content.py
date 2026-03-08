from app import db
from datetime import datetime


class Project(db.Model):
    __tablename__ = "projects"

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    slug = db.Column(db.String(200), unique=True, nullable=False)
    description = db.Column(db.Text, nullable=True)
    short_desc = db.Column(db.String(300), nullable=True)
    category = db.Column(db.String(80), nullable=False)  # e.g. "web", "webgl", "fullstack"
    tech_stack = db.Column(db.String(400), nullable=True)  # comma-separated tags
    thumbnail_url = db.Column(db.String(500), nullable=True)  # external image URL
    live_url = db.Column(db.String(500), nullable=True)
    github_url = db.Column(db.String(500), nullable=True)
    featured = db.Column(db.Boolean, default=False)
    order = db.Column(db.Integer, default=0)
    published = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    @property
    def tech_list(self):
        if self.tech_stack:
            return [t.strip() for t in self.tech_stack.split(",") if t.strip()]
        return []

    def __repr__(self):
        return f"<Project {self.title}>"


class Video(db.Model):
    __tablename__ = "videos"

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    slug = db.Column(db.String(200), unique=True, nullable=False)
    description = db.Column(db.Text, nullable=True)
    short_desc = db.Column(db.String(300), nullable=True)
    category = db.Column(db.String(80), nullable=False)  # e.g. "brand-film", "motion", "reel"
    platform = db.Column(db.String(40), nullable=False, default="youtube")  # youtube, instagram, vimeo, other
    video_url = db.Column(db.String(500), nullable=False)  # raw URL pasted by admin
    embed_id = db.Column(db.String(200), nullable=True)   # extracted ID for embedding
    thumbnail_url = db.Column(db.String(500), nullable=True)
    duration = db.Column(db.String(20), nullable=True)    # e.g. "3:24"
    tools_used = db.Column(db.String(300), nullable=True) # comma-separated
    featured = db.Column(db.Boolean, default=False)
    order = db.Column(db.Integer, default=0)
    published = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    @property
    def embed_url(self):
        if self.platform == "youtube" and self.embed_id:
            return f"https://www.youtube.com/embed/{self.embed_id}?autoplay=1&rel=0"
        if self.platform == "vimeo" and self.embed_id:
            return f"https://player.vimeo.com/video/{self.embed_id}?autoplay=1"
        return self.video_url

    @property
    def tools_list(self):
        if self.tools_used:
            return [t.strip() for t in self.tools_used.split(",") if t.strip()]
        return []

    def __repr__(self):
        return f"<Video {self.title}>"
