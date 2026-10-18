# Deliberately insecure sample for FlaskShield. DO NOT deploy.
from flask import Flask

app = Flask(__name__)
app.secret_key = "secret"
app.config["DEBUG"] = True
app.config["SESSION_COOKIE_SECURE"] = False
app.config["SESSION_COOKIE_HTTPONLY"] = False
app.config["DB_PASSWORD"] = "hunter2"
app.config["API_KEY"] = "sk_live_abcdef1234567890"


@app.route("/")
def home():
    return "hello"


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
