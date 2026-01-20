import os
from flask import Flask, render_template
from .config import DevConfig, TestConfig
from .extensions import db, csrf, limiter
from .security_headers import apply_security_headers
from .db import init_db

def create_app(config_name: str | None = None) -> Flask:
    app = Flask(__name__)

    cfg = config_name or os.getenv("FLASK_CONFIG", "dev")
    if cfg == "test":
        app.config.from_object(TestConfig)
    else:
        app.config.from_object(DevConfig)

    # Extensions
    db.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)

    # Blueprints
    from .auth import bp as auth_bp
    from .routes import bp as main_bp
    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)

    # Security headers + optional HTTPS redirect
    apply_security_headers(app)

    # Error handlers (no info leak)
    @app.errorhandler(400)
    def bad_request(_): return render_template("base.html", title="400", body="Bad request"), 400

    @app.errorhandler(401)
    def unauthorized(_): return render_template("base.html", title="401", body="Unauthorized"), 401

    @app.errorhandler(403)
    def forbidden(_): return render_template("base.html", title="403", body="Forbidden"), 403

    @app.errorhandler(404)
    def not_found(_): return render_template("base.html", title="404", body="Not found"), 404

    @app.errorhandler(429)
    def rate_limited(_): return render_template("base.html", title="429", body="Too many requests"), 429

    @app.errorhandler(500)
    def server_error(_): return render_template("base.html", title="500", body="Server error"), 500

    # Init DB (demo amaçlı; prod’da migration önerilir)
    init_db(app)

    return app
