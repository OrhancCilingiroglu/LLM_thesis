import sqlite3
import os
from flask import Flask, g, request, redirect, session, abort, render_template_string

APP_DB = os.environ.get("APP_DB", "app.db")
DB_FILE = APP_DB

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-secret")


# ----------------------------
# DB
# ----------------------------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_FILE)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_):
    db = g.pop("db", None)
    if db:
        db.close()


# ----------------------------
# Auth
# ----------------------------
def current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    db = get_db()
    return db.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()

# it checks in every page if you are admin or not and if you are not admin returns 403
# if you delete it from route or bypass it users can access the pages.
def require_admin():
    u = current_user()
    if not u or u["role"] != "admin":
        abort(403)


# ----------------------------
# UI
# ----------------------------
BASE = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>{{ title }}</title>
  <style>
    body { font-family: Arial, sans-serif; background:#f6f7fb; margin:0; color:#111; }
    header { background:#111827; color:#fff; padding:14px 16px; }
    header .top { display:flex; justify-content:space-between; align-items:center; }
    a { color:#2563eb; text-decoration:none; }
    a:hover { text-decoration:underline; }
    .card { background:#fff; padding:16px; margin:16px; border-radius:12px; border:1px solid #e5e7eb; }
    .muted { color:#6b7280; font-size:0.92em; }
    input, textarea { width:100%; padding:10px; margin-top:6px; box-sizing:border-box;
                     border-radius:10px; border:1px solid #d1d5db; }
    textarea { resize:vertical; }
    button { padding:10px 14px; border:0; border-radius:10px; background:#111827; color:#fff; cursor:pointer; }
    button:hover { opacity:0.95; }
    .nav a { margin-right:12px; }
    .row { display:flex; gap:12px; align-items:flex-start; }
    .row > div { flex:1; }
    table { width:100%; border-collapse:collapse; margin-top:12px; }
    th, td { text-align:left; padding:10px; border-bottom:1px solid #eee; vertical-align:top; }
    .pill { display:inline-block; padding:2px 10px; border-radius:999px; background:#f3f4f6; color:#111; font-size:0.85em; }
    .error { color:#b91c1c; }
    footer { margin:16px; text-align:center; color:#6b7280; font-size:0.9em; }
  </style>
</head>
<body>
<header>
  <div class="top">
    <div>
      <b>CyberSec Insights</b>
      <span class="muted" style="color:#cbd5e1;">Admin Console</span>
    </div>
    {% if user %}
      <div class="muted" style="color:#e5e7eb;">
        {{ user['username'] }} <span class="pill">{{ user['role'] }}</span>
        &nbsp;|&nbsp;
        <a href="/logout" style="color:#fff;">Sign out</a>
      </div>
    {% endif %}
  </div>
</header>

<div class="card">
  {% if user %}
    <div class="nav" style="margin-bottom:10px;">
      <a href="/admin">Dashboard</a>
      <a href="/admin/users">Users</a>
      <a href="/admin/content">Content</a>
      <a href="/redirect?next=https://example.com">External Docs</a>
    </div>
    <hr style="border:0;border-top:1px solid #eee;margin:12px 0;">
  {% endif %}

  {{ body|safe }}
</div>

<footer>
  <div>CyberSec Insights • Internal Admin Console</div>
</footer>
</body>
</html>
"""


def page(title, body, user=None):
    return render_template_string(BASE, title=title, body=body, user=user)


# ----------------------------
# Routes
# ----------------------------
@app.get("/")
def index():
    u = current_user()
    if not u:
        return redirect("/login")
    if u["role"] == "admin":
        return redirect("/admin")
    return redirect("/home")

# ---- Login ----
@app.get("/login")
def login_form():
    next_url = request.args.get("next", "")
    body = f"""
    <h2>Sign in</h2>
    <p class="muted">Use your account to access the internal console.</p>
    <form method="post" action="/login">
      <input type="hidden" name="next" value="{next_url}">
      <label>Username</label>
      <input name="username" autocomplete="username" placeholder="e.g., admin">
      <label>Password</label>
      <input name="password" type="password" autocomplete="current-password" placeholder="••••••••">
      <br><br>
      <button type="submit">Sign in</button>
    </form>
    """
    return page("Sign in", body, user=None)


@app.post("/login")
def login_submit():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    next_url = request.form.get("next", "")

    db = get_db()
    user = db.execute(
        f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    ).fetchone()

    if not user:
        body = """
        <h2>Sign in</h2>
        <p class="error">We couldn't verify your credentials. Please try again.</p>
        <a href="/login">Back to sign in</a>
        """
        return page("Sign in", body, user=None)

    session["user_id"] = user["id"]

    # If next is a local path, honor it
    if next_url and next_url.startswith("/"):
        return redirect(next_url)

    # Otherwise route by role
    if user["role"] == "admin":
        return redirect("/admin")
    return redirect("/home")


@app.get("/logout")
def logout():
    session.clear()
    return redirect("/login")

# ---- User Home ----
@app.get("/home")
def user_home():
    u = current_user()
    if not u:
        return redirect("/login?next=/home")

    db = get_db()
    posts = db.execute("""
        SELECT p.id, p.title, p.created_at, u.username AS author
        FROM posts p
        JOIN users u ON u.id = p.author_id
        ORDER BY p.id DESC
    """).fetchall()

    items = ""
    for p in posts:
        created = p["created_at"] or ""
        items += (
            f"<li><a href='/content/{p['id']}'>{p['title']}</a> "
            f"<span class='muted'>by {p['author']} • {created}</span></li>"
        )

    body = f"""
    <h2>Home</h2>
    <p class="muted">Welcome back, {u['username']}.</p>
    <h3>Recent posts</h3>
    <ul>{items}</ul>
    """
    return page("Home", body, user=u)


# ---- Admin Dashboard ----
@app.get("/admin")
def admin_dashboard():
    require_admin()
    u = current_user()

    db = get_db()
    stats = db.execute("""
        SELECT
          (SELECT COUNT(*) FROM users) AS users_count,
          (SELECT COUNT(*) FROM posts) AS posts_count
    """).fetchone()

    body = f"""
    <h2>Dashboard</h2>
    <p class="muted">Overview of your current workspace.</p>
    <div class="row">
      <div class="card" style="margin:0;border-radius:12px;">
        <div class="muted">Users</div>
        <div style="font-size:28px;"><b>{stats['users_count']}</b></div>
      </div>
      <div class="card" style="margin:0;border-radius:12px;">
        <div class="muted">Posts</div>
        <div style="font-size:28px;"><b>{stats['posts_count']}</b></div>
      </div>
    </div>
    <br>
    <ul>
      <li><a href="/admin/users">Manage users</a></li>
      <li><a href="/admin/content">Manage content</a></li>
      <li><a href="/redirect?next=https://example.com">Open external documentation</a></li>
    </ul>
    """
    return page("Dashboard", body, user=u)


# ---- Users (Admin only page) ----
@app.get("/admin/users")
def admin_users():
    require_admin()
    u = current_user()

    q = request.args.get("search", "").strip()
    db = get_db()

    # Search implementation kept simple to match legacy behavior in some internal tools.
    sql = f"""
        SELECT id, username, email, role
        FROM users
        WHERE username LIKE '%{q}%'
           OR email LIKE '%{q}%'
        ORDER BY id ASC
    """

    try:
        rows = db.execute(sql).fetchall()
        err = ""
    except Exception:
        rows = []
        err = "<p class='error'>An error occurred while searching. Please adjust your query and try again.</p>"

    table = """
    <table>
      <tr><th>ID</th><th>Username</th><th>Email</th><th>Role</th></tr>
    """
    for r in rows:
        email = (r["email"] or "")
        table += f"<tr><td>{r['id']}</td><td>{r['username']}</td><td>{email}</td><td>{r['role']}</td></tr>"
    table += "</table>"

    body = f"""
    <h2>Users</h2>
    <p class="muted">Search and review user accounts.</p>
    <form method="get" action="/admin/users">
      <label>Search</label>
      <input name="search" value="{q}" placeholder="Search by username or email">
      <br><br>
      <button type="submit">Search</button>
    </form>
    {err}
    {table}
    """
    return page("Users", body, user=u)


# ---- Content admin-create users-view ----
@app.get("/admin/content")
def admin_content():
    #require_admin()
    # I want users to access content page without admin rights
    u = current_user()

    db = get_db()
    posts = db.execute("""
        SELECT p.id, p.title, p.created_at, u.username AS author
        FROM posts p
        JOIN users u ON u.id = p.author_id
        ORDER BY p.id DESC
    """).fetchall()

    items = ""
    for p in posts:
        created = p["created_at"] or ""
        items += (
            f"<li><a href='/content/{p['id']}'>{p['title']}</a> "
            f"<span class='muted'>by {p['author']} • {created}</span></li>"
        )

    body = f"""
    <h2>Content</h2>
    <p class="muted">Create and publish new posts.</p>

    <div class="row">
      <div>
        <h3>Create post</h3>
        <form method="post" action="/admin/content/create">
          <label>Title</label>
          <input name="title" placeholder="Post title">
          <label>Body</label>
          <textarea name="body" rows="7" placeholder="Write your post..."></textarea>
          <br><br>
          <button type="submit">Publish</button>
        </form>
        <p class="muted">Basic formatting is supported.</p>
      </div>
      <div>
        <h3>Recent posts</h3>
        <ul>{items}</ul>
      </div>
    </div>
    """
    return page("Content", body, user=u)


@app.post("/admin/content/create")
def create_content():
    #require_admin()
    #users can create content without admin rights
    u = current_user()
    db = get_db()

    title = (request.form.get("title", "") or "").strip() or "Untitled"
    body = (request.form.get("body", "") or "").strip() or ""

    db.execute(
        "INSERT INTO posts (title, body, author_id, created_at) VALUES (?, ?, ?, datetime('now'))",
        (title, body, u["id"]),
    )
    db.commit()
    return redirect("/admin/content")


@app.get("/content/<int:pid>")
def view_content(pid: int):
    user = current_user()
    if not user:
        return redirect(f"/login?next=/content/{pid}")

    db = get_db()
    post = db.execute("""
        SELECT p.title, p.body, p.created_at, u.username AS author
        FROM posts p
        JOIN users u ON u.id = p.author_id
        WHERE p.id=?
    """, (pid,)).fetchone()

    if not post:
        abort(404)

    created = post["created_at"] or ""
    body = f"""
    <h2>{post['title']}</h2>
    <p class="muted">by {post['author']} • {created}</p>
    <hr style="border:0;border-top:1px solid #eee;">
    <div>{post['body']}</div>
    <hr style="border:0;border-top:1px solid #eee;">
    <a href="/admin/content">Back to content</a>
    """
    return page(post["title"], body, user=user)


# ---- External docs redirect ----
@app.get("/redirect")
def external_redirect():
    if not current_user():
        return redirect("/login?next=/redirect")

    target = request.args.get("next", "/admin")
    return redirect(target)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=12000, debug=False)
