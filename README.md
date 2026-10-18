# FlaskShield: Secure Configuration Audit Tool

A Flask web app that statically audits other Flask projects for insecure configuration.
Uploaded code is **never executed**: Python is parsed with `ast`, config files with
`configparser`/`json`/line parsers.

## Run
    pip install -r requirements.txt
    python run.py            # http://127.0.0.1:5000
    pytest                   # run tests

## Checks
| ID | Check | Severity |
|----|-------|----------|
| FS001 | Debug mode enabled (`DEBUG=True`, `app.run(debug=True)`) | Critical |
| FS002 | Missing / weak / hardcoded `SECRET_KEY` | High / Medium |
| FS003 | Session cookie flags (Secure, HttpOnly, SameSite) | Medium / Low |
| FS004 | Missing security headers (CSP, X-Frame-Options, HSTS, nosniff, Referrer-Policy) | Medium / Low |
| FS005 | Hardcoded passwords, tokens, API keys, credentialed URIs | High |

Score = 100 minus weighted findings (Critical 25, High 15, Medium 8, Low 3).

## Layout
- `flaskshield/scanner/` collector (AST + config parsers), `rules.py`, `engine.py`
- `flaskshield/` app factory, routes, SQLite (`sqlite3`) layer, safe zip upload handling, templates
- `samples/` `insecure_app` and `secure_app` test fixtures
- `tests/` rule and web tests
- SQLite DB: `flaskshield.db` (tables `scans`, `findings`); logs: `logs/flaskshield.log`

 
