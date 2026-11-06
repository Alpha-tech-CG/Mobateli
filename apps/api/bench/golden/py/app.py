import hashlib
import os
import pickle
import random
import secrets
import shlex
import sqlite3
import subprocess

import jwt
import requests
import yaml
from flask import Flask, request

app = Flask(__name__)
db = sqlite3.connect("app.db")


# ---- SQL injection -----------------------------------------------------------
@app.route("/user")
def user():
    uid = request.args.get("id")
    cur = db.execute("SELECT * FROM users WHERE id = " + uid)  # VULN: SQLI
    return str(cur.fetchall())


@app.route("/search")
def search():
    q = request.args.get("q")
    cur = db.execute(f"SELECT * FROM items WHERE name LIKE '%{q}%'")  # VULN: SQLI
    return str(cur.fetchall())


@app.route("/report")
def report():
    year = request.args.get("year")
    query = "SELECT * FROM sales WHERE year = %s" % year
    cur = db.execute(query)  # VULN: SQLI
    return str(cur.fetchall())


@app.route("/safe-user")
def safe_user():
    cur = db.execute("SELECT * FROM users WHERE id = ?", (request.args.get("id"),))  # SAFE: SQLI
    return str(cur.fetchall())


# ---- Command injection -------------------------------------------------------
@app.route("/ping")
def ping():
    host = request.args.get("host")
    os.system("ping -c 1 " + host)  # VULN: CMDI
    return "ok"


@app.route("/lookup")
def lookup():
    domain = request.args.get("domain")
    out = subprocess.check_output("nslookup " + domain, shell=True)  # VULN: CMDI
    return out


@app.route("/safe-lookup")
def safe_lookup():
    domain = request.args.get("domain")
    out = subprocess.check_output(["nslookup", domain])  # SAFE: CMDI
    return out


@app.route("/quoted")
def quoted():
    name = shlex.quote(request.args.get("name"))
    subprocess.run("echo " + name, shell=True)  # SAFE: CMDI
    return "ok"


def disk_usage():
    return subprocess.run("df -h", shell=True, capture_output=True)  # SAFE: CMDI


# ---- Code injection ----------------------------------------------------------
@app.route("/calc")
def calc():
    return str(eval(request.args.get("expr")))  # VULN: CODEI


@app.route("/run")
def run():
    code = request.form["code"]
    exec(code)  # VULN: CODEI
    return "done"


# ---- Deserialization ---------------------------------------------------------
@app.route("/session", methods=["POST"])
def session():
    state = pickle.loads(request.data)  # VULN: DESER
    return str(state)


@app.route("/config", methods=["POST"])
def config():
    cfg = yaml.load(request.data)  # VULN: DESER
    return str(cfg)


@app.route("/safe-config", methods=["POST"])
def safe_config():
    cfg = yaml.safe_load(request.data)  # SAFE: DESER
    return str(cfg)


def load_settings(path):
    with open(path) as fh:
        return yaml.load(fh, Loader=yaml.SafeLoader)  # SAFE: DESER


# ---- Path traversal ----------------------------------------------------------
@app.route("/file")
def read_file():
    name = request.args.get("name")
    with open(os.path.join("/srv/files", name)) as fh:  # VULN: PATH
        return fh.read()


# ---- SSRF --------------------------------------------------------------------
@app.route("/fetch")
def fetch():
    return requests.get(request.args.get("url")).text  # VULN: SSRF


def status():
    return requests.get("https://status.example.com/health", timeout=5).status_code  # SAFE: SSRF


# ---- Crypto / TLS / JWT ------------------------------------------------------
def hash_password(pw):
    return hashlib.md5(pw.encode()).hexdigest()  # VULN: HASH


def file_digest(data):
    return hashlib.sha256(data).hexdigest()  # SAFE: HASH


def reset_token():
    return "".join(random.choice("abcdef0123456789") for _ in range(32))  # VULN: RANDOM


def safe_token():
    return secrets.token_hex(32)  # SAFE: RANDOM


def call_partner(url):
    return requests.get(url, verify=False)  # VULN: TLS


def call_partner_safe(url):
    return requests.get(url, verify=True, timeout=5)  # SAFE: TLS


def read_claims(token):
    return jwt.decode(token, options={"verify_signature": False})  # VULN: JWT


def read_claims_safe(token, key):
    return jwt.decode(token, key, algorithms=["RS256"])  # SAFE: JWT
