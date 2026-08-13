# appsec-cicd-pipeline

Automated application security pipeline that embeds SAST, SBOM,
dependency scanning, and DAST into CI/CD — with a Python policy
gate that fails builds on critical findings.

## Architecture

```
push / PR
   │
   ├── SAST ......... Semgrep (OWASP Top 10, secrets, security-audit)
   ├── SBOM ......... Syft            (Day 3)
   ├── Dep vulns .... Grype           (Day 3)
   ├── DAST ......... OWASP ZAP baseline vs demo app   (Day 5)
   │
   └── Orchestrator (Python)          (Day 4)
        • ingest + normalize all findings
        • deduplicate
        • apply security-policy.yml thresholds
        • emit JSON + HTML report
        • exit non-zero → build fails on policy violation
```

## Components

- `demo-app/` — deliberately vulnerable Flask app used as the scan
  target (SQLi, XSS, hardcoded secrets, weak hashing, outdated deps).
  **Never deploy this.**
- `.github/workflows/security-scan.yml` — CI pipeline
- `orchestrator/` — Python findings aggregator + policy gate
- `security-policy.yml` — severity thresholds and suppression rules

## Status

- [x] Day 1: repo structure + vulnerable demo app
- [x] Day 2: Semgrep SAST in CI
- [ ] Day 3: Syft SBOM + Grype dependency scanning
- [ ] Day 4: Python orchestrator + policy gate
- [ ] Day 5: OWASP ZAP baseline DAST + HTML report
- [ ] Day 6: docs, screenshots, badges
