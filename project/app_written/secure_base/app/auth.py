from flask import Blueprint, render_template, request, redirect, session, abort, flash, url_for
from werkzeug.security import generate_password_hash, check_password_hash

from .extensions import db, limiter
from .models import User
from .validators import validate_username, is_safe_redirect_target

bp = Blueprint("auth", __name__)

@bp.get("/register")
def register_form():
    return render_template("register.html")

@bp.post("/register")
def register_submit():
    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""

    if not validate_username(username) or len(password) < 10:
        flash("Invalid username or password too short.", "error")
        return redirect(url_for("auth.register_form"))

    exists = db.session.query(User.id).filter_by(username=username).first()
    if exists:
        flash("Username already exists.", "error")
        return redirect(url_for("auth.register_form"))

    u = User(
        username=username,
        password_hash=generate_password_hash(password),
        role="user",
    )
    db.session.add(u)
    db.session.commit()
    flash("Registered. Please login.", "ok")
    return redirect(url_for("auth.login_form"))

@bp.get("/login")
def login_form():
    return render_template("login.html", next=request.args.get("next", ""))

@bp.post("/login")
@limiter.limit("5 per minute")  # brute force control
def login_submit():
    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""
    next_url = request.form.get("next") or ""

    user = db.session.query(User).filter_by(username=username).first()
    if not user or not check_password_hash(user.password_hash, password):
        flash("Invalid credentials.", "error")
        return redirect(url_for("auth.login_form"))

    session.clear()
    session["user_id"] = user.id

    # safe redirect (CWE-601 prevention)
    if next_url and is_safe_redirect_target(next_url):
        return redirect(next_url)

    return redirect(url_for("main.home"))

@bp.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("auth.login_form"))

def current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    return db.session.get(User, uid)

def require_login(user):
    if not user:
        abort(401)

def require_role(user, role: str):
    require_login(user)
    if user.role != role:
        abort(403)
