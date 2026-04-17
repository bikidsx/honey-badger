import os
import sqlite3
from flask import Flask, request

app = Flask(__name__)
DB_PASSWORD = "supersecret123"

def get_db():
    conn = sqlite3.connect("app.db")
    return conn

@app.route("/user")
def get_user():
    user_id = request.args.get("id")
    conn = get_db()
    cursor = conn.cursor()
    # SQL injection: string concatenation
    cursor.execute("SELECT * FROM users WHERE id = " + user_id)
    return str(cursor.fetchone())

@app.route("/exec")
def run_command():
    cmd = request.args.get("cmd")
    # Command injection
    result = os.popen(cmd).read()
    return result

@app.route("/fetch")
def fetch_url():
    import requests
    url = request.args.get("url")
    # SSRF
    resp = requests.get(url)
    return resp.text
