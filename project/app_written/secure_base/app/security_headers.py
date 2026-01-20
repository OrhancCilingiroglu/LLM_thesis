from flask import request, redirect

def apply_security_headers(app):
    @app.after_request
    def _set_headers(resp):
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Content-Security-Policy"] = app.config["CSP"]

        # HSTS only meaningful over HTTPS
        if request.is_secure:
            resp.headers["Strict-Transport-Security"] = (
                f"max-age={app.config['HSTS_MAX_AGE']}; includeSubDomains"
            )
        return resp

    @app.before_request
    def _force_https():
        if app.config.get("FORCE_HTTPS") and not request.is_secure:
            return redirect(request.url.replace("http://", "https://", 1), code=301)
