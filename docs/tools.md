# Security Tools Reference

## Tool comparison

| | Semgrep | Dependency-Check | SonarQube |
|---|---|---|---|
| **Type** | SAST | SCA | SAST + Quality Gate |
| **What it scans** | Your code | Third-party libraries | Your code |
| **Finds** | Insecure code patterns | Known CVEs in dependencies | Security hotspots + vulnerabilities |
| **Speed** | ~30 seconds | ~30 seconds (with --noupdate) | ~25 seconds |
| **Languages** | PHP, C#, JS, Python, Go… | Any (reads lock files) | PHP, JS, C#, Java… |
| **False positive rate** | Low–Medium | Medium–High | Low |
| **Custom rules** | ✅ Yes — YAML format | ✅ Suppression file | ✅ Quality profiles |

---

## Semgrep

### Rulesets used

| Ruleset | Rules | What it covers |
|---|---|---|
| `p/php` | ~23 | PHP-specific security — SQL injection, XSS, RCE |
| `p/csharp` | ~15 | C#-specific security — injection, cryptography |
| `p/owasp-top-ten` | ~varies | OWASP Top 10 across all languages |
| `p/security-audit` | ~varies | General secrets, dangerous functions |

### Severity levels

- **ERROR** — blocks the pipeline. Must be fixed before code can proceed.
- **WARNING** — does not block. Posted as GitLab comment for developer awareness.

### Custom rules

Custom rules are stored in `rules/custom-security-rules.yml`. They target patterns specific to your codebase that community rulesets miss — hardcoded secrets in your config format, missing authorisation checks in your framework's controller pattern, etc.

To add a custom rule, add a new entry to the YAML file and commit to this repository. It applies to all projects on their next push.

### False positive management

To suppress a specific Semgrep finding, add a comment above the line:

```php
// nosemgrep: rule-id
$query = "SELECT * FROM users"; // safe — no user input
```

---

## Dependency-Check

### What it scans

Reads lock files and compares package versions against the NVD CVE database:

| File | Package manager |
|---|---|
| `composer.lock` | PHP / Composer |
| `packages.lock.json` | .NET / NuGet |
| `package-lock.json` | Node.js / npm |
| `yarn.lock` | Node.js / Yarn |

### CVSS threshold

The pipeline fails on CVSS ≥ 7.0 (HIGH and CRITICAL). MEDIUM findings are reported but do not block.

### NVD database

The local NVD database is updated daily by the `dependency-check-db-update` Jenkins job. Pipeline scans use `--noupdate` to avoid the 20-minute download on every scan.

If the update job fails, scans continue using the cached database. Monitor the update job — stale data means missed CVEs.

### False positives

Dependency-Check sometimes matches packages by name pattern rather than exact match, producing false positives. Manage these with `dc-suppressions.xml`. Follow the documented process — never suppress without review.

### CISA Known Exploited Vulnerabilities

Dependency-Check fetches the CISA KEV catalogue. CVEs on this list have confirmed active exploitation in the wild and should be treated as urgent regardless of CVSS score.

---

## SonarQube

### Quality Gate — Security Gate

The custom Security Gate fails if:
- Any security hotspot is unreviewed
- Any confirmed vulnerability exists

This is stricter than the default SonarQube gate which focuses on code quality metrics.

### Security hotspots vs vulnerabilities

| Type | Meaning | Who acts |
|---|---|---|
| **Hotspot** | Code pattern that **may** be a risk — needs human review | Security team reviews; developer fixes if confirmed |
| **Vulnerability** | Confirmed security issue | Developer must fix |

### Quality Profile

Use a custom Quality Profile for your language that activates all security-relevant rules:
- All rules tagged `owasp-top-10`
- All rules tagged `cwe`
- All rules tagged `sans-top-25`

In **SonarQube → Quality Profiles → PHP → Copy → activate security rules → assign to project**.

### Two tokens

SonarQube requires two separate tokens:
- **`sonarqube-token`** — used by the scanner to push analysis results (write)
- **`sonarqube-read-token`** — used by `generate-report.py` to fetch findings for the HTML report (read)

The read token needs the **Browse** permission on each project.
