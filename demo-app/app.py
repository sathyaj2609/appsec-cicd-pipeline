"""
Deliberately vulnerable demo application.
Purpose: acts as the scan target for the AppSec CI/CD pipeline.
DO NOT deploy this anywhere public. Each flaw is labeled so scanner
findings can be verified against known-bad code.
"""
import hashlib
import sqlite3

from flask import Flask, request, render_template_string

app = Flask(__name__)

# FLAW 1: Hardcoded secret (should be detected by Semgrep secrets rules)
app.secret_key = "super-secret-key-12345"
API_TOKEN = "sk_live_51HxTest0000000000000000"

DB = "demo.db"


def init_db():
    conn = sqlite3.connect(DB)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users "
        "(id INTEGER PRIMARY KEY, username TEXT, password_hash TEXT)"
    )
    conn.commit()
    conn.close()


@app.route("/user")
def get_user():
    username = request.args.get("username", "")
    conn = sqlite3.connect(DB)
    # FLAW 2: SQL injection - user input concatenated into query
    query = "SELECT id, username FROM users WHERE username = '" + username + "'"
    rows = conn.execute(query).fetchall()
    conn.close()
    return {"results": rows}


@app.route("/greet")
def greet():
    name = request.args.get("name", "friend")
    # FLAW 3: Reflected XSS - unsanitized input rendered into template
    return render_template_string("<h1>Hello " + name + "!</h1>")


@app.route("/register", methods=["POST"])
def register():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    # FLAW 4: Weak hashing - MD5 for passwords
    password_hash = hashlib.md5(password.encode()).hexdigest()
    conn = sqlite3.connect(DB)
    conn.execute(
        "INSERT INTO users (username, password_hash) VALUES (?, ?)",
        (username, password_hash),
    )
    conn.commit()
    conn.close()
    return {"status": "registered"}


@app.route("/health")
def health():
    return {"status": "ok"}


if __name__ == "__main__":
    init_db()
    # FLAW 5: Debug mode enabled in production entrypoint
    app.run(host="0.0.0.0", debug=True)
