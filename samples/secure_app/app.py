import os

from flask import Flask

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ["SECRET_KEY"],
    DEBUG=False,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    DB_PASSWORD=os.environ.get("DB_PASSWORD"),
)


@app.after_request
def set_headers(resp):
    resp.headers["Content-Security-Policy"] = "default-src 'self'"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "same-origin"
    return resp


@app.route("/")
def home():
    return "hello"
