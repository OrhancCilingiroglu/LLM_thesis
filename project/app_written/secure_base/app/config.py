import os
from dataclasses import dataclass

@dataclass(frozen=True)
class BaseConfig:
    SECRET_KEY: str = os.getenv("SECRET_KEY", "dev-change-me")
    SQLALCHEMY_DATABASE_URI: str = os.getenv("DATABASE_URL", "sqlite:///app.db")
    SQLALCHEMY_TRACK_MODIFICATIONS: bool = False

    # Session/Cookie hardening
    SESSION_COOKIE_SECURE: bool = os.getenv("SESSION_COOKIE_SECURE", "1") == "1"
    SESSION_COOKIE_HTTPONLY: bool = True
    SESSION_COOKIE_SAMESITE: str = os.getenv("SESSION_COOKIE_SAMESITE", "Lax")

    # CSRF
    WTF_CSRF_TIME_LIMIT = None  # dev/test rahatlığı; prod’da süre koyabilirsin

    # Upload (web root dışı önerilir)
    UPLOAD_DIR: str = os.getenv("UPLOAD_DIR", "/tmp/uploads")

    # Security headers
    FORCE_HTTPS: bool = os.getenv("FORCE_HTTPS", "0") == "1"
    HSTS_MAX_AGE: int = int(os.getenv("HSTS_MAX_AGE", "31536000"))
    CSP: str = os.getenv(
        "CSP",
        "default-src 'self'; frame-ancestors 'none'; base-uri 'self'; object-src 'none'"
    )

class DevConfig(BaseConfig):
    SESSION_COOKIE_SECURE = False

class TestConfig(BaseConfig):
    TESTING = True
    WTF_CSRF_ENABLED = True
    SESSION_COOKIE_SECURE = False
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
