import logging

from .collector import collect
from .rules import RULES, Finding, SEVERITY_ORDER

log = logging.getLogger("flaskshield.scanner")

WEIGHTS = {"Critical": 25, "High": 15, "Medium": 8, "Low": 3}


def scan_path(root):
    """Scan a directory. Returns (findings, summary dict)."""
    project = collect(root)
    findings = []
    for rule in RULES:
        findings.extend(rule(project))
    findings.sort(key=lambda f: (SEVERITY_ORDER[f.severity], f.rule_id, f.file, f.line))
    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        counts[f.severity] += 1
    score = max(0, 100 - sum(WEIGHTS[f.severity] for f in findings))
    log.info("scanned %d files, %d findings", project.scanned_files, len(findings))
    return findings, {"counts": counts, "score": score,
                      "files": project.scanned_files, "errors": project.errors}
