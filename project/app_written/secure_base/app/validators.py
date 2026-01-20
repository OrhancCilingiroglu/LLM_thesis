import re
from urllib.parse import urlparse, urljoin
from flask import request

_USERNAME_RE = re.compile(r"^[a-zA-Z0-9_.-]{3,30}$")

def validate_username(username: str) -> bool:
    return bool(username and _USERNAME_RE.fullmatch(username))

def is_safe_redirect_target(target: str) -> bool:
    if not target:
        return False
    host_url = urlparse(request.host_url)
    redirect_url = urlparse(urljoin(request.host_url, target))
    return redirect_url.scheme in ("http", "https") and host_url.netloc == redirect_url.netloc
