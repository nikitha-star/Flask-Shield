import logging
import os
import tempfile

from flask import (Blueprint, Response, abort, current_app, flash, redirect,
                   render_template, request, url_for)

from .db import get_db, save_scan
from .scanner import scan_path
from .uploads import UploadError, save_upload

bp = Blueprint("main", __name__)
log = logging.getLogger("flaskshield.web")


def _samples():
    d = current_app.config["SAMPLES_DIR"]
    return sorted(n for n in os.listdir(d) if os.path.isdir(os.path.join(d, n)) and not n.startswith("."))


@bp.get("/")
def home():
    return render_template("home.html", samples=_samples())


@bp.get("/new")
def new_scan():
    recent = get_db().execute("SELECT * FROM scans ORDER BY id DESC LIMIT 5").fetchall()
    return render_template("new_scan.html", samples=_samples(), recent=recent)


@bp.post("/scan")
def scan_upload():
    f = request.files.get("project")
    if f is None:
        flash("Choose a file to scan.", "danger")
        return redirect(url_for("main.new_scan"))
    with tempfile.TemporaryDirectory(prefix="flaskshield_") as tmp:
        try:
            name = save_upload(f, tmp)
        except UploadError as e:
            log.warning("rejected upload: %s", e)
            flash(str(e), "danger")
            return redirect(url_for("main.new_scan"))
        findings, summary = scan_path(tmp)
    sid = save_scan(name, "upload", findings, summary)
    log.info("scan %d complete for upload %r", sid, name)
    return redirect(url_for("main.scan_detail", scan_id=sid))


@bp.post("/scan/sample/<name>")
def scan_sample(name):
    if name not in _samples():
        abort(404)
    findings, summary = scan_path(os.path.join(current_app.config["SAMPLES_DIR"], name))
    sid = save_scan(name, "sample", findings, summary)
    log.info("scan %d complete for sample %r", sid, name)
    return redirect(url_for("main.scan_detail", scan_id=sid))


@bp.get("/history")
def history():
    scans = get_db().execute("SELECT * FROM scans ORDER BY id DESC").fetchall()
    return render_template("history.html", scans=scans)


def _load(scan_id):
    db = get_db()
    scan = db.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    if scan is None:
        abort(404)
    order = "CASE severity WHEN 'Critical' THEN 0 WHEN 'High' THEN 1 WHEN 'Medium' THEN 2 ELSE 3 END"
    findings = db.execute(
        f"SELECT * FROM findings WHERE scan_id = ? ORDER BY {order}, rule_id, id", (scan_id,)).fetchall()
    return scan, findings


@bp.get("/scan/<int:scan_id>")
def scan_detail(scan_id):
    scan, findings = _load(scan_id)
    return render_template("scan.html", scan=scan, findings=findings, download=False)


@bp.get("/scan/<int:scan_id>/report")
def report(scan_id):
    scan, findings = _load(scan_id)
    html = render_template("report.html", scan=scan, findings=findings)
    return Response(html, mimetype="text/html", headers={
        "Content-Disposition": f'attachment; filename="flaskshield-report-{scan_id}.html"'})


@bp.post("/scan/<int:scan_id>/delete")
def delete(scan_id):
    db = get_db()
    db.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
    db.commit()
    log.info("deleted scan %d", scan_id)
    return redirect(url_for("main.history"))
