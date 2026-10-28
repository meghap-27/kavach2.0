"""Intentionally vulnerable demo app (command injection). For scanner testing only."""
import os
import shlex
import subprocess

from flask import Flask, request

from utils import archive_logs, build_report

app = Flask(__name__)


@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    os.system("ping -c 1 " + host)  # ZDS:CMD-D1
    return "ok"


@app.route("/lookup", methods=["POST"])
def lookup():
    domain = request.form["domain"]
    out = subprocess.check_output(f"nslookup {domain}", shell=True)  # ZDS:CMD-D2
    return out


@app.route("/report")
def report():
    name = request.args.get("name", "daily")
    return build_report(name)


@app.route("/archive/<folder>")
def archive(folder):
    archive_logs(folder)
    return "archived"


@app.route("/safe-ping")
def safe_ping():
    host = request.args.get("host", "")
    os.system("ping -c 1 " + shlex.quote(host))  # ZDS:CMD-N1
    return "ok"
