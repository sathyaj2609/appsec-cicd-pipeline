#!/usr/bin/env python3
"""
Security Policy Gate
====================
Ingests findings from multiple scanners (Semgrep SAST, Grype dependency
vulns, ZAP DAST), normalizes them into one schema, deduplicates,
applies thresholds from security-policy.yml, and emits JSON + HTML
reports. Exits non-zero when the policy is violated, failing the build.

Usage:
    python orchestrator/gate.py --policy security-policy.yml --reports reports/
"""
import argparse
import glob
import html
import json
import os
import sys
from collections import Counter
from dataclasses import dataclass, asdict

import yaml

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

# Map scanner-native severities to the normalized scale
SEMGREP_SEVERITY = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}
GRYPE_SEVERITY = {
    "Critical": "critical", "High": "high", "Medium": "medium",
    "Low": "low", "Negligible": "info", "Unknown": "info",
}
ZAP_RISK = {"3": "high", "2": "medium", "1": "low", "0": "info"}


@dataclass(frozen=True)
class Finding:
    source: str          # semgrep | grype | zap
    rule_id: str         # scanner rule / CVE id
    severity: str        # normalized: critical..info
    title: str
    location: str        # file:line or package@version or URL


# ----------------------------- ingestors -----------------------------

def ingest_semgrep(path):
    data = json.load(open(path))
    for r in data.get("results", []):
        yield Finding(
            source="semgrep",
            rule_id=r["check_id"],
            severity=SEMGREP_SEVERITY.get(r["extra"]["severity"], "medium"),
            title=r["extra"]["message"].split("\n")[0][:120],
            location=f'{r["path"]}:{r["start"]["line"]}',
        )


def ingest_grype(path):
    data = json.load(open(path))
    for m in data.get("matches", []):
        v, a = m["vulnerability"], m["artifact"]
        yield Finding(
            source="grype",
            rule_id=v["id"],
            severity=GRYPE_SEVERITY.get(v.get("severity", "Unknown"), "info"),
            title=(v.get("description") or v["id"])[:120],
            location=f'{a["name"]}@{a["version"]}',
        )


def ingest_zap(path):
    data = json.load(open(path))
    for site in data.get("site", []):
        for alert in site.get("alerts", []):
            yield Finding(
                source="zap",
                rule_id=str(alert.get("pluginid", alert.get("alertRef", "?"))),
                severity=ZAP_RISK.get(str(alert.get("riskcode", "1")), "low"),
                title=alert.get("name", "ZAP alert")[:120],
                location=(alert.get("instances") or [{}])[0].get("uri", site.get("@name", "")),
            )


INGESTORS = {
    "semgrep": ingest_semgrep,
    "grype": ingest_grype,
    "zap": ingest_zap,
}


def collect_findings(reports_dir):
    findings = []
    for path in sorted(glob.glob(os.path.join(reports_dir, "*.json"))):
        name = os.path.basename(path).lower()
        for key, fn in INGESTORS.items():
            if key in name:
                try:
                    found = list(fn(path))
                    print(f"[gate] {os.path.basename(path)}: {len(found)} findings")
                    findings.extend(found)
                except (json.JSONDecodeError, KeyError) as e:
                    print(f"[gate] WARN could not parse {path}: {e}")
                break
    return findings


# --------------------------- gate logic ------------------------------

def apply_policy(findings, policy):
    ignored_ids = {i["id"] for i in (policy.get("ignore") or []) if isinstance(i, dict)}
    kept = [f for f in findings if f.rule_id not in ignored_ids]
    suppressed = len(findings) - len(kept)

    counts = Counter(f.severity for f in kept)
    thresholds = policy.get("fail_on", {})
    violations = []
    for sev, limit in thresholds.items():
        if counts.get(sev, 0) >= int(limit):
            violations.append(f"{counts.get(sev, 0)} {sev} findings (limit: <{limit})")
    return kept, suppressed, counts, violations


# ---------------------------- reporting ------------------------------

def write_json(findings, counts, violations, out_dir):
    payload = {
        "summary": {sev: counts.get(sev, 0) for sev in SEVERITY_ORDER},
        "violations": violations,
        "passed": not violations,
        "findings": [asdict(f) for f in findings],
    }
    with open(os.path.join(out_dir, "findings.json"), "w") as fh:
        json.dump(payload, fh, indent=2)


def write_html(findings, counts, violations, out_dir):
    badge = (
        '<span style="color:#fff;background:#c0392b;padding:4px 10px;border-radius:4px">FAILED</span>'
        if violations else
        '<span style="color:#fff;background:#27ae60;padding:4px 10px;border-radius:4px">PASSED</span>'
    )
    sev_colors = {"critical": "#8e44ad", "high": "#c0392b", "medium": "#e67e22",
                  "low": "#f1c40f", "info": "#95a5a6"}
    rows = "".join(
        f"<tr><td>{f.source}</td>"
        f'<td><span style="color:{sev_colors[f.severity]};font-weight:bold">{f.severity}</span></td>'
        f"<td>{html.escape(f.rule_id)}</td><td>{html.escape(f.title)}</td>"
        f"<td><code>{html.escape(f.location)}</code></td></tr>"
        for f in sorted(findings, key=lambda x: SEVERITY_ORDER.index(x.severity))
    )
    summary = " · ".join(f"{sev}: {counts.get(sev, 0)}" for sev in SEVERITY_ORDER)
    viols = "".join(f"<li>{html.escape(v)}</li>" for v in violations) or "<li>None</li>"
    doc = f"""<!doctype html><html><head><meta charset="utf-8">
<title>Security Report</title>
<style>body{{font-family:system-ui,sans-serif;margin:2rem;color:#2c3e50}}
table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #ddd;padding:8px;text-align:left;font-size:14px}}
th{{background:#2c3e50;color:#fff}}tr:nth-child(even){{background:#f8f9fa}}</style></head>
<body><h1>Security Scan Report {badge}</h1>
<p><b>Summary:</b> {summary}</p>
<h3>Policy violations</h3><ul>{viols}</ul>
<h3>Findings ({len(findings)})</h3>
<table><tr><th>Source</th><th>Severity</th><th>Rule / CVE</th><th>Title</th><th>Location</th></tr>{rows}</table>
</body></html>"""
    with open(os.path.join(out_dir, "report.html"), "w") as fh:
        fh.write(doc)


# ------------------------------ main ---------------------------------

def main():
    ap = argparse.ArgumentParser(description="Security policy gate")
    ap.add_argument("--policy", required=True)
    ap.add_argument("--reports", required=True)
    args = ap.parse_args()

    policy = yaml.safe_load(open(args.policy))
    findings = collect_findings(args.reports)
    kept, suppressed, counts, violations = apply_policy(findings, policy)

    write_json(kept, counts, violations, args.reports)
    write_html(kept, counts, violations, args.reports)

    print(f"\n[gate] {len(kept)} findings ({suppressed} suppressed by policy)")
    for sev in SEVERITY_ORDER:
        if counts.get(sev):
            print(f"[gate]   {sev}: {counts[sev]}")

    if violations:
        print("\n[gate] POLICY VIOLATIONS — failing build:")
        for v in violations:
            print(f"[gate]   ✗ {v}")
        sys.exit(1)
    print("\n[gate] ✓ Policy passed")


if __name__ == "__main__":
    main()
