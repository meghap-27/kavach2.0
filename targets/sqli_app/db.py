"""Data helpers for sqli_app. Intentionally vulnerable."""
import sqlite3


def _conn():
    return sqlite3.connect("app.db")


def _fetch(query):
    cur = _conn().cursor()
    cur.execute(query)  # ZDS:SQL-W1
    return cur.fetchall()


def find_user_by(column, value):
    return _fetch("SELECT * FROM users WHERE %s = '%s'" % (column, value))


def _like_clause(text):
    return "name LIKE '%" + text + "%'"


def search_items(term):
    clause = _like_clause(term)
    cur = _conn().cursor()
    cur.executescript("SELECT * FROM items WHERE " + clause)  # ZDS:SQL-W2
    return cur.fetchall()


def purge_table(name):
    _conn().execute("DELETE FROM " + name)  # ZDS:SQL-N2
