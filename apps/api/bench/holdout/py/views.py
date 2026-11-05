import hashlib
import json
import marshal
import os
import random
import ssl
import subprocess
import urllib.request

import httpx
import jwt
import requests
import yaml
from django.db import connection
from flask import Flask, request, send_file
from werkzeug.utils import secure_filename

from .models import User

app = Flask(__name__)
UPLOAD = "/srv/uploads"


# ---- SQL (Django) ------------------------------------------------------------
def by_name(request):
    with connection.cursor() as cursor:
        cursor.execute("SELECT * FROM t WHERE n = '%s'" % request.GET["n"])  # VULN: SQLI
        return cursor.fetchall()


def search_users(request):
    return list(User.objects.raw(f"SELECT * FROM users WHERE name LIKE '{request.GET.get('q')}'"))  # VULN: SQLI


def by_name_safe(request):
    with connection.cursor() as cursor:
        cursor.execute("SELECT * FROM t WHERE n = %s", [request.GET["n"]])  # SAFE: SQLI
        return cursor.fetchall()


# ---- Commands ----------------------------------------------------------------
@app.route("/convert", methods=["POST"])
def convert():
    subprocess.Popen(f"convert {request.form['f']} out.png", shell=True)  # VULN: CMDI
    return "ok"


@app.route("/list")
def listing():
    p = request.args["p"]
    return os.popen("ls " + p).read()  # VULN: CMDI


@app.route("/convert-safe", methods=["POST"])
def convert_safe():
    subprocess.run(["convert", request.form["f"], "out.png"])  # SAFE: CMDI
    return "ok"


# ---- Files -------------------------------------------------------------------
@app.route("/download")
def download():
    return send_file(os.path.join(UPLOAD, request.args["f"]))  # VULN: PATH


@app.route("/log")
def log():
    with open(request.args.get("log")) as fh:  # VULN: PATH
        return fh.read()


@app.route("/download-safe")
def download_safe():
    name = secure_filename(request.args["f"])
    return send_file(os.path.join(UPLOAD, name))  # SAFE: PATH


def read_config(path):
    with open(path) as fh:  # SAFE: PATH
        return fh.read()


# ---- Outbound requests -------------------------------------------------------
@app.route("/fetch", methods=["POST"])
def fetch():
    return httpx.get(request.json["url"]).text  # VULN: SSRF


@app.route("/open")
def open_url():
    return urllib.request.urlopen(request.args["u"]).read()  # VULN: SSRF


@app.route("/item")
def item():
    item_id = int(request.args["id"])
    return requests.get(f"https://api.example.com/items/{item_id}", timeout=5).text  # SAFE: SSRF


# ---- Deserialization ---------------------------------------------------------
@app.route("/state", methods=["POST"])
def state():
    return str(marshal.loads(request.data))  # VULN: DESER


@app.route("/cfg", methods=["POST"])
def cfg():
    return str(yaml.load(request.data, Loader=yaml.Loader))  # VULN: DESER


@app.route("/json", methods=["POST"])
def as_json():
    return str(json.loads(request.data))  # SAFE: DESER


# ---- Code injection ----------------------------------------------------------
@app.route("/run", methods=["POST"])
def run_code():
    exec(compile(request.form["src"], "<user>", "exec"))  # VULN: CODEI
    return "done"


# ---- Crypto / random / TLS / JWT --------------------------------------------
def store_password(password):
    return hashlib.sha1(password.encode()).hexdigest()  # VULN: HASH


def etag(body):
    return hashlib.sha256(body).hexdigest()  # SAFE: HASH


def new_session():
    session_id = str(random.randint(0, 10**9))  # VULN: RANDOM
    return session_id


def deal(cards):
    random.shuffle(cards)  # SAFE: RANDOM
    return cards


def partner_context():
    return ssl._create_unverified_context()  # VULN: TLS


def notify(url, payload):
    return requests.post(url, json=payload, verify=False)  # VULN: TLS


def claims(token, key):
    return jwt.decode(token, key, algorithms=["none"])  # VULN: JWT


def claims_safe(token, key):
    return jwt.decode(token, key, algorithms=["HS256"], audience="api")  # SAFE: JWT
