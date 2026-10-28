"""Intentionally vulnerable demo app (SQL injection). For scanner testing only."""
import sqlite3

from flask import Flask, request

from db import find_user_by, search_items

app = Flask(__name__)


def get_db():
    return sqlite3.connect("app.db")


@app.route("/user")
def user():
    uid = request.args.get("id", "")
    cur = get_db().cursor()
    cur.execute("SELECT * FROM users WHERE id = " + uid)  # ZDS:SQL-D1
    return str(cur.fetchall())


@app.route("/order/<order_id>")
def order(order_id):
    cur = get_db().cursor()
    cur.execute(f"SELECT * FROM orders WHERE id = '{order_id}'")  # ZDS:SQL-D2
    return str(cur.fetchall())


@app.route("/profile")
def profile():
    email = request.args.get("email", "")
    return str(find_user_by("email", email))


@app.route("/search", methods=["POST"])
def search():
    term = request.get_json().get("q", "")
    return str(search_items(term))


@app.route("/safe-user")
def safe_user():
    uid = request.args.get("id", "")
    cur = get_db().cursor()
    cur.execute("SELECT * FROM users WHERE id = ?", (uid,))  # ZDS:SQL-N1
    return str(cur.fetchall())
