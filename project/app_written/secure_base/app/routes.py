from flask import Blueprint, render_template
from .auth import current_user, require_role

bp = Blueprint("main", __name__)

@bp.get("/")
def home():
    user = current_user()
    return render_template("home.html", user=user)

@bp.get("/admin")
def admin():
    user = current_user()
    require_role(user, "admin")
    return render_template("admin.html", user=user)
