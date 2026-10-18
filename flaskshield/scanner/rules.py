"""Security rules. Each rule takes a Project and returns a list of Finding."""
import math
import re
from dataclasses import dataclass

from .collector import LITERAL, ENV, DYNAMIC

CRITICAL, HIGH, MEDIUM, LOW = "Critical", "High", "Medium", "Low"
SEVERITY_ORDER = {CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3}


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    file: str
    line: int
    description: str
    recommendation: str


def _loc(s):
    return (s.file, s.line) if s else ("-", 0)


def _truthy(v):
    return v is True or (isinstance(v, str) and v.lower() in ("true", "1", "yes", "on"))


def check_debug(p):
    out = []
    for s in p.settings:
        if s.key == "DEBUG" and s.kind == LITERAL and _truthy(s.value):
            out.append(Finding(
                "FS001", "Debug mode enabled", CRITICAL, s.file, s.line,
                "DEBUG is set to True. The Werkzeug debugger allows arbitrary code execution "
                "and leaks source code and configuration in tracebacks.",
                "Set DEBUG=False in production and never pass debug=True to app.run(). "
                "Drive it from an environment variable defaulting to False."))
    return out


WEAK_KEYS = {"secret", "secretkey", "secret_key", "changeme", "change-me", "password", "default",
             "dev", "development", "test", "testing", "key", "flask", "admin", "12345", "123456",
             "your-secret-key", "your_secret_key", "supersecret", "super-secret", "mysecret",
             "s3cr3t", "keep it secret", "keep-it-secret"}


def _entropy(s):
    return -sum(c / len(s) * math.log2(c / len(s)) for c in (s.count(x) for x in set(s))) if s else 0


def check_secret_key(p):
    s = p.get("SECRET_KEY")
    if s is None:
        if not p.flask_files:
            return []
        return [Finding(
            "FS002", "No SECRET_KEY configured", MEDIUM, p.flask_files[0], 0,
            "No SECRET_KEY was found. Sessions and signed cookies cannot be used securely without one.",
            "Set SECRET_KEY from an environment variable or secret store, e.g. "
            "app.config['SECRET_KEY'] = os.environ['SECRET_KEY'].")]
    if s.kind != LITERAL:
        return []
    v = s.value
    if not isinstance(v, (str, bytes)) or not v:
        return [Finding("FS002", "Empty SECRET_KEY", HIGH, s.file, s.line,
                        "SECRET_KEY is empty or not a string.", "Use a long random value from the environment.")]
    text = v.decode("latin-1") if isinstance(v, bytes) else v
    weak = text.strip().lower() in WEAK_KEYS or len(text) < 16 or _entropy(text) < 3.0
    if weak:
        return [Finding(
            "FS002", "Weak or default SECRET_KEY", HIGH, s.file, s.line,
            "SECRET_KEY is hardcoded and short, predictable or a well-known default. "
            "Attackers can forge session cookies.",
            "Generate a key with `python -c 'import secrets; print(secrets.token_hex(32))'` "
            "and load it from the environment.")]
    return [Finding(
        "FS002", "SECRET_KEY hardcoded in source", MEDIUM, s.file, s.line,
        "SECRET_KEY is a literal in the code or config, so it is exposed to anyone with repository access.",
        "Move the key to an environment variable or secret manager and rotate the current value.")]


def check_cookies(p):
    out = []
    secure = p.get("SESSION_COOKIE_SECURE")
    if secure is None or (secure.kind == LITERAL and not _truthy(secure.value)):
        f, l = _loc(secure)
        out.append(Finding(
            "FS003", "SESSION_COOKIE_SECURE not enabled", MEDIUM, f, l,
            "Session cookies may be sent over plain HTTP, where they can be intercepted.",
            "Set SESSION_COOKIE_SECURE=True and serve the app over HTTPS."))
    http = p.get("SESSION_COOKIE_HTTPONLY")
    if http is not None and http.kind == LITERAL and not _truthy(http.value):
        out.append(Finding(
            "FS003", "SESSION_COOKIE_HTTPONLY disabled", MEDIUM, http.file, http.line,
            "JavaScript can read the session cookie, so any XSS bug leads to session theft.",
            "Set SESSION_COOKIE_HTTPONLY=True (the Flask default)."))
    same = p.get("SESSION_COOKIE_SAMESITE")
    if same is None or (same.kind == LITERAL and str(same.value).lower() in ("none", "")):
        f, l = _loc(same)
        out.append(Finding(
            "FS003", "SESSION_COOKIE_SAMESITE not restricted", LOW, f, l,
            "Without SameSite=Lax or Strict the cookie is sent on cross-site requests, aiding CSRF.",
            "Set SESSION_COOKIE_SAMESITE='Lax' (or 'Strict')."))
    return out


HEADERS = [
    ("content-security-policy", "Content-Security-Policy", MEDIUM,
     "Mitigates XSS and data injection by restricting content sources."),
    ("x-frame-options", "X-Frame-Options", MEDIUM, "Prevents clickjacking by blocking framing."),
    ("strict-transport-security", "Strict-Transport-Security", MEDIUM,
     "Forces browsers to use HTTPS for future requests."),
    ("x-content-type-options", "X-Content-Type-Options", LOW,
     "Stops MIME-type sniffing (set to 'nosniff')."),
    ("referrer-policy", "Referrer-Policy", LOW, "Limits URL information leaked in the Referer header."),
]
HEADER_LIBS = {"flask_talisman", "talisman", "secure"}


def check_headers(p):
    if not p.flask_files or p.imports & HEADER_LIBS:
        return []
    out = []
    for key, name, sev, why in HEADERS:
        if not any(key in s for s in p.strings):
            out.append(Finding(
                "FS004", f"Missing security header: {name}", sev, p.flask_files[0], 0,
                f"No code sets {name}. {why}",
                f"Add it in an @app.after_request handler (response.headers['{name}'] = ...) "
                "or use the Flask-Talisman extension."))
    return out


SENSITIVE = re.compile(r"(PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|PRIVATE_KEY|ACCESS_KEY|CREDENTIAL)", re.I)
SAFE_VALUES = {"", "none", "null", "changeme"}
URI_PW = re.compile(r"://[^:/\s]+:[^@\s]+@")


def check_sensitive(p):
    out, seen = [], set()
    for s in p.settings:
        if s.key == "SECRET_KEY" or s.kind != LITERAL or not isinstance(s.value, str):
            continue
        if s.value.strip().lower() in SAFE_VALUES:
            continue
        hit = SENSITIVE.search(s.key) or (s.key.endswith(("_URI", "_URL")) and URI_PW.search(s.value))
        if hit and (s.file, s.line, s.key) not in seen:
            seen.add((s.file, s.line, s.key))
            out.append(Finding(
                "FS005", f"Hardcoded sensitive setting: {s.key}", HIGH, s.file, s.line,
                f"{s.key} holds a literal credential. Committed secrets leak through version control and backups.",
                "Load the value from an environment variable or secret manager and rotate the exposed credential."))
    return out


RULES = [check_debug, check_secret_key, check_cookies, check_headers, check_sensitive]
