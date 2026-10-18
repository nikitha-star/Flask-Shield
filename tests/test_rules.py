import io
import os
import sys
import zipfile

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from flaskshield import create_app
from flaskshield.scanner import scan_path

SAMPLES = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "samples")


def scan_src(tmp_path, code, name="app.py"):
    (tmp_path / name).write_text(code)
    findings, summary = scan_path(str(tmp_path))
    return findings, summary


def ids(findings):
    return {f.rule_id for f in findings}


def test_insecure_sample_hits_every_rule():
    findings, summary = scan_path(os.path.join(SAMPLES, "insecure_app"))
    assert ids(findings) == {"FS001", "FS002", "FS003", "FS004", "FS005"}
    assert summary["counts"]["Critical"] >= 1
    assert summary["score"] == 0


def test_secure_sample_is_clean():
    findings, summary = scan_path(os.path.join(SAMPLES, "secure_app"))
    assert findings == []
    assert summary["score"] == 100


def test_debug_run_kwarg(tmp_path):
    f, _ = scan_src(tmp_path, "from flask import Flask\napp=Flask(__name__)\napp.run(debug=True)\n")
    assert "FS001" in ids(f)


def test_debug_false_not_flagged(tmp_path):
    f, _ = scan_src(tmp_path, "DEBUG = False\n")
    assert "FS001" not in ids(f)


def test_missing_secret_key(tmp_path):
    f, _ = scan_src(tmp_path, "from flask import Flask\napp=Flask(__name__)\n")
    assert any(x.title == "No SECRET_KEY configured" for x in f)


def test_strong_hardcoded_key_is_medium(tmp_path):
    f, _ = scan_src(tmp_path, "SECRET_KEY = 'f3a9c1d27b8e4a6054d1e9b7c3a2f680'\n")
    x = [i for i in f if i.rule_id == "FS002"][0]
    assert x.severity == "Medium"


def test_env_secret_key_ok(tmp_path):
    f, _ = scan_src(tmp_path, "import os\nSECRET_KEY = os.environ.get('SECRET_KEY', 'dev')\n")
    assert "FS002" not in ids(f)


def test_config_file_parsing(tmp_path):
    f, _ = scan_src(tmp_path, "DEBUG=true\nSECRET_KEY=password\nDB_PASSWORD=abc\n", name=".env")
    assert {"FS001", "FS002", "FS005"} <= ids(f)


def test_json_and_ini(tmp_path):
    (tmp_path / "c.json").write_text('{"flask": {"DEBUG": true}}')
    (tmp_path / "c.ini").write_text("[app]\nAPI_TOKEN = abc123\n")
    f, _ = scan_path(str(tmp_path))
    assert {"FS001", "FS005"} <= ids(f)


def test_talisman_suppresses_header_findings(tmp_path):
    f, _ = scan_src(tmp_path, "from flask import Flask\nfrom flask_talisman import Talisman\n"
                              "app=Flask(__name__)\nTalisman(app)\n")
    assert "FS004" not in ids(f)


def test_syntax_error_reported_not_fatal(tmp_path):
    _, s = scan_src(tmp_path, "def (:\n")
    assert s["errors"]


@pytest.fixture
def client(tmp_path):
    app = create_app({"TESTING": True, "DATABASE": str(tmp_path / "t.db"), "LOG_DIR": str(tmp_path)})
    return app.test_client()


def test_sample_scan_history_and_report(client):
    r = client.post("/scan/sample/insecure_app")
    assert r.status_code == 302
    assert b"Debug mode enabled" in client.get(r.headers["Location"]).data
    assert b"insecure_app" in client.get("/history").data
    rep = client.get(r.headers["Location"] + "/report")
    assert "attachment" in rep.headers["Content-Disposition"]
    assert client.post(r.headers["Location"] + "/delete").status_code == 302
    assert client.get(r.headers["Location"]).status_code == 404


def test_upload_zip(client):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("proj/app.py", "DEBUG = True\n")
    buf.seek(0)
    r = client.post("/scan", data={"project": (buf, "proj.zip")}, content_type="multipart/form-data")
    assert r.status_code == 302 and "/scan/" in r.headers["Location"]


def test_zip_path_traversal_rejected(client):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("../evil.py", "x=1")
    buf.seek(0)
    r = client.post("/scan", data={"project": (buf, "e.zip")}, content_type="multipart/form-data",
                    follow_redirects=True)
    assert b"unsafe path" in r.data


def test_bad_extension_rejected(client):
    r = client.post("/scan", data={"project": (io.BytesIO(b"x"), "a.exe")},
                    content_type="multipart/form-data", follow_redirects=True)
    assert b"Unsupported" in r.data
