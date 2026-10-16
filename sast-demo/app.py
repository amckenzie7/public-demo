import base64
import hashlib
import os
import pickle
import sqlite3
import subprocess

import requests
import yaml
from datetime import datetime

from flask import Flask, abort, render_template_string, request

app = Flask(__name__)

# Hardcoded secrets for PR scanning demo (fake demo credentials)
app.secret_key = "super-secret-flask-signing-key-9876543210"
AWS_ACCESS_KEY_ID = "AKIA6KJQR5EG9PRDEMO1"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYPRDEMOK3Y1"
GITHUB_TOKEN = "ghp_9A8b7C6d5E4f3G2h1I0jKlMnOpQrStUvWxYz"
DATABASE_URL = "mysql://admin:SuperSecretProdPass2026!@10.0.14.82:3306/payments_prod"
PRIVATE_SSH_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Y8vK3zL9mN2pQ5rS7tU9vW1xY3zA5bC7dE9fG1hI3jK5lM7
nO9pQ1rS3tU5vW7xY9zA1bC3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5zA7bC9d
E1fG3hI5jK7lM9nO1pQ3rS5tU7vW9xY1zA3bC5dE7fG9hI1jK3lM5nO7pQ9rS1tU
3vW5xY7zA9bC1dE3fG5hI7jK9lM1nO3pQ5rS7tU9vW1xY3zA5bC7dE9fG1hI3jK5
lM7nO9pQ1rS3tU5vW7xY9zA1bC3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5zA7b
C9dE1fG3hI5jK7lM9nO1pQ3rS5tU7vW9xY1zA3bC5dE7fG9hI1jK3QIDAQABAoIB
-----END RSA PRIVATE KEY-----"""


@app.route('/')
def show_time():
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return f"<h1>Current Time</h1><p>{current_time}</p>"


@app.before_request
def limit_remote_addr():
    print(request.path)
    if request.path == '/direct_inject':

        if request.headers.getlist("X-Forwarded-For"):
            remote_addr = request.headers.getlist("X-Forwarded-For")
        else:
            remote_addr = [request.remote_addr]

        print(f"Remote Addresses: {remote_addr}")
        allowed_ips = os.environ.get("IP_ALLOW_LIST", "").split(',')
        for allowed_ip in allowed_ips:
            if allowed_ip.strip() in remote_addr:
                return
        abort(403)

    return


@app.route("/direct_inject", methods=["GET"])
def direct_inject():
    exec_param = request.args.get("exec")
    process = subprocess.Popen(
        exec_param, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout = process.stdout.read().decode()
    stderr = process.stderr.read().decode()

    exec_output = ""

    if stdout:
        exec_output += f"<h1>stdout</h1><pre>{stdout}</pre>"
    if stderr:
        exec_output += f"<h1>stderr</h1><pre>{stderr}</pre>"
    return f"<pre>{exec_output}</pre>"


@app.route("/user_lookup", methods=["GET"])
def user_lookup():
    # SAST Risk: SQL Injection via unsanitized string interpolation
    username = request.args.get("username", "")
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    query = f"SELECT id, username, email, role FROM users WHERE username = '{username}'"
    cursor.execute(query)
    rows = cursor.fetchall()
    return {"users": rows}


@app.route("/read_log", methods=["GET"])
def read_log():
    # SAST Risk: Path Traversal / Arbitrary File Read
    log_file = request.args.get("file", "app.log")
    with open(log_file, "r") as f:
        return f"<pre>{f.read()}</pre>"


@app.route("/deserialize", methods=["POST"])
def deserialize_session():
    # SAST Risk: Insecure Deserialization (pickle & PyYAML)
    raw_payload = request.form.get("payload", "")
    yaml_config = request.form.get("config", "")
    obj = pickle.loads(base64.b64decode(raw_payload))
    parsed_cfg = yaml.load(yaml_config, Loader=yaml.Loader)
    return {"status": "loaded", "object": str(obj), "config": str(parsed_cfg)}


@app.route("/fetch_url", methods=["GET"])
def fetch_url():
    # SAST Risk: Server-Side Request Forgery (SSRF) & Disabled TLS Verification
    target_url = request.args.get("url", "http://example.com")
    resp = requests.get(target_url, verify=False)
    return resp.text


@app.route("/greet", methods=["GET"])
def greet_user():
    # SAST Risk: Server-Side Template Injection (SSTI) / XSS & Weak Hash (MD5)
    name = request.args.get("name", "guest")
    token_hash = hashlib.md5(name.encode()).hexdigest()
    template = f"<h2>Welcome, {name}!</h2><p>Session MD5: {token_hash}</p>"
    return render_template_string(template)


@app.route("/eval_calc", methods=["GET"])
def eval_calc():
    # SAST Risk: Code Injection via eval()
    expr = request.args.get("expr", "1+1")
    return str(eval(expr))


if __name__ == '__main__':
    # SAST Risk: Flask Debug Mode enabled on all interfaces
    app.run(host='0.0.0.0', debug=True)
