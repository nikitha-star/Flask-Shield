import sqlite3

from flask import current_app, g

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    source TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    files_scanned INTEGER NOT NULL DEFAULT 0,
    score INTEGER NOT NULL DEFAULT 100,
    critical INTEGER NOT NULL DEFAULT 0,
    high INTEGER NOT NULL DEFAULT 0,
    medium INTEGER NOT NULL DEFAULT 0,
    low INTEGER NOT NULL DEFAULT 0,
    errors TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    rule_id TEXT NOT NULL,
    title TEXT NOT NULL,
    severity TEXT NOT NULL,
    file TEXT NOT NULL,
    line INTEGER NOT NULL,
    description TEXT NOT NULL,
    recommendation TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
"""


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(current_app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


def close_db(_exc=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db(path):
    con = sqlite3.connect(path)
    con.executescript(SCHEMA)
    con.commit()
    con.close()


def save_scan(name, source, findings, summary):
    db = get_db()
    c = summary["counts"]
    cur = db.execute(
        "INSERT INTO scans (name, source, files_scanned, score, critical, high, medium, low, errors) "
        "VALUES (?,?,?,?,?,?,?,?,?)",
        (name, source, summary["files"], summary["score"], c["Critical"], c["High"],
         c["Medium"], c["Low"], "\n".join(summary["errors"])))
    sid = cur.lastrowid
    db.executemany(
        "INSERT INTO findings (scan_id, rule_id, title, severity, file, line, description, recommendation) "
        "VALUES (?,?,?,?,?,?,?,?)",
        [(sid, f.rule_id, f.title, f.severity, f.file, f.line, f.description, f.recommendation)
         for f in findings])
    db.commit()
    return sid
