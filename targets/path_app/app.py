"""Intentionally vulnerable demo app (path traversal). For scanner testing only."""
import os

from flask import Flask, request, send_file
from werkzeug.utils import secure_filename

from storage import export_attachment, read_note

app = Flask(__name__)
BASE = "/srv/files"


@app.route("/download")
def download():
    name = request.args.get("file", "")
    return open(os.path.join(BASE, name)).read()  # ZDS:PATH-D1


@app.route("/avatar/<user>")
def avatar(user):
    path = BASE + "/avatars/" + user + ".png"
    return send_file(path)  # ZDS:PATH-D2


@app.route("/note")
def note():
    nid = request.args.get("id", "")
    return read_note(nid)


@app.route("/export", methods=["POST"])
def export():
    upload = request.files["doc"]
    return export_attachment(upload.filename)


@app.route("/safe-download")
def safe_download():
    name = secure_filename(request.args.get("file", ""))
    return open(os.path.join(BASE, name)).read()  # ZDS:PATH-N1
