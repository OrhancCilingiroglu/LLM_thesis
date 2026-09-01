"""
auth_detection.py
==================
Detects whether a generated Flask sample has a usable login flow, and if so
extracts what ZAP needs to authenticate against it: the login route, the
form field names, and one seeded (username, password) pair.

Pure functions over already-stored `code`/`sql_script` columns -- no Docker,
no ZAP, no network. Checked against real samples first: ~37% of the
docker-successful corpus (5,022/13,634) has both a `/login`-style route and
a seeded plaintext credential; the rest either have no login at all (many
of these apps are single-purpose, no auth model) or store only a password
*hash* (e.g. `password_hash` with a real pbkdf2 digest), which is
detected and deliberately treated as NOT usable -- there is no way to
recover the plaintext from a hash, so attempting to log in with the hash
itself would just fail silently and look like "no vulnerabilities behind
login" when the real reason is "we never actually logged in".
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# "username"/"password" dominate overwhelmingly in the corpus (8,570 / 8,404
# occurrences across all form-field reads, next closest is "email" at 1,682),
# so they anchor the search, but the field actually used is still read out of
# the code rather than assumed, in case a given sample varies.
_ROUTE_RE = re.compile(
    r"""@app\.route\(\s*['"](?P<path>/[^'"]*)['"][^)]*\)\s*\n\s*def\s+\w+\s*\([^)]*\)\s*:
        (?P<body>(?:\n[ \t].*)+)""",
    re.VERBOSE,
)
_FORM_FIELD_RE = re.compile(
    r"""request\.form(?:\.get)?\s*[\[\(]\s*['"](?P<field>[a-zA-Z_]+)['"]"""
)
_LOGIN_HINT_RE = re.compile(r"\blogin\b", re.IGNORECASE)


@dataclass(frozen=True)
class LoginRoute:
    path: str
    username_field: str
    password_field: str


def detect_login_route(code: str) -> LoginRoute | None:
    """Find a route whose handler reads both a username-like and a
    password-like form field. Prefers a route whose path/name mentions
    "login"; falls back to the first route with both fields present.
    """
    if not code:
        return None

    candidates: list[LoginRoute] = []
    for match in _ROUTE_RE.finditer(code):
        path = match.group("path")
        body = match.group("body")
        fields = {f.lower() for f in _FORM_FIELD_RE.findall(body)}
        username_field = next((f for f in fields if "user" in f and "confirm" not in f), None)
        password_field = next(
            (f for f in ("password", "passwd", "pwd") if f in fields), None
        )
        if username_field and password_field:
            candidates.append(LoginRoute(path, username_field, password_field))

    if not candidates:
        return None
    for candidate in candidates:
        if _LOGIN_HINT_RE.search(candidate.path):
            return candidate
    return candidates[0]


# --------------------------------------------------------------------------- #
# Seeded credential extraction
# --------------------------------------------------------------------------- #

_CREATE_TABLE_RE = re.compile(
    r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?[`\"']?(?P<table>\w+)[`\"']?\s*\((?P<cols>[^;]+?)\)\s*;",
    re.IGNORECASE | re.DOTALL,
)
_INSERT_RE = re.compile(
    r"INSERT\s+INTO\s+[`\"']?(?P<table>\w+)[`\"']?\s*\((?P<cols>[^)]+)\)\s*VALUES\s*(?P<values>.+?);",
    re.IGNORECASE | re.DOTALL,
)
# A password value that looks like a hash rather than plaintext. Three
# independent signals, any one is enough -- checked against real samples:
# passlib/bcrypt style "$pbkdf2-sha256$29000$salt$hash" (note the hyphen in
# the scheme name, which \w alone does not match -- the first version of
# this regex missed it); Werkzeug's generate_password_hash default
# "pbkdf2:sha256:260000$salt$hash" (no leading $ at all); and, as a
# catch-all, any long contiguous hex run that plaintext demo passwords
# ("password1", "wonderland") never happen to contain. False "looks hashed"
# positives just mean we skip auth for that sample, which is safe; false
# negatives would mean attempting to log in with a hash as the password,
# which fails and silently looks like "no vulnerabilities behind login".
_DOLLAR_HASH_RE = re.compile(r"^\$[\w-]+\$")
_HASH_SCHEME_RE = re.compile(r"(?i)\b(pbkdf2|bcrypt|scrypt|argon2)\b")
_LONG_HEX_RUN_RE = re.compile(r"[0-9a-f]{32,}", re.IGNORECASE)


def _looks_like_hash(value: str) -> bool:
    return bool(
        _DOLLAR_HASH_RE.match(value)
        or _HASH_SCHEME_RE.search(value)
        or _LONG_HEX_RUN_RE.search(value)
    )


def _split_top_level_commas(s: str) -> list[str]:
    """Split on commas that are not inside a quoted string. Good enough for
    the simple, single-line seed values these generated apps use -- not a
    general SQL tokenizer.
    """
    parts, current, quote = [], [], None
    for ch in s:
        if quote:
            current.append(ch)
            if ch == quote:
                quote = None
        elif ch in ("'", '"'):
            quote = ch
            current.append(ch)
        elif ch == "," :
            parts.append("".join(current))
            current = []
        else:
            current.append(ch)
    parts.append("".join(current))
    return [p.strip() for p in parts]


def _unquote(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
        return value[1:-1]
    return value


def extract_seeded_credentials(sql_script: str) -> tuple[str, str] | None:
    """Return one (username, password) pair from the seed data, or None if
    no table has both a username-like and a plaintext-looking password-like
    column, or the values can't be parsed with confidence.
    """
    if not sql_script:
        return None

    # column order per table, from CREATE TABLE, so INSERTs that omit an
    # explicit column list can still be mapped positionally if needed later
    table_columns: dict[str, list[str]] = {}
    for m in _CREATE_TABLE_RE.finditer(sql_script):
        cols = []
        for line in m.group("cols").split(","):
            line = line.strip()
            if not line:
                continue
            name = line.split()[0].strip("`\"'")
            if name.upper() in ("PRIMARY", "FOREIGN", "UNIQUE", "CHECK", "CONSTRAINT"):
                continue
            cols.append(name.lower())
        if cols:
            table_columns[m.group("table").lower()] = cols

    for m in _INSERT_RE.finditer(sql_script):
        columns = [c.strip().strip("`\"'").lower() for c in m.group("cols").split(",")]
        username_idx = next((i for i, c in enumerate(columns) if "username" in c or c == "user"), None)
        password_idx = next((i for i, c in enumerate(columns) if c in ("password", "passwd", "pwd")), None)
        if username_idx is None or password_idx is None:
            continue  # e.g. password_hash -- deliberately not matched, see _HASH_LIKE_RE too

        first_row = _split_top_level_commas(
            re.split(r"\)\s*,\s*\(", m.group("values").strip().lstrip("(").rstrip(")"))[0]
        )
        if len(first_row) != len(columns):
            continue  # row shape didn't match the column list -- don't guess

        username = _unquote(first_row[username_idx])
        password = _unquote(first_row[password_idx])
        if not username or not password or _looks_like_hash(password):
            continue
        return username, password

    return None


@dataclass(frozen=True)
class AuthCandidate:
    login_path: str
    username_field: str
    password_field: str
    username: str
    password: str


def detect_auth_candidate(code: str, sql_script: str) -> AuthCandidate | None:
    """Combine route detection and credential extraction. Both must succeed."""
    route = detect_login_route(code)
    if route is None:
        return None
    creds = extract_seeded_credentials(sql_script)
    if creds is None:
        return None
    username, password = creds
    return AuthCandidate(route.path, route.username_field, route.password_field, username, password)
