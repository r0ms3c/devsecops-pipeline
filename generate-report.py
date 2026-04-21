#!/usr/bin/env python3
"""
Security Scan Report Generator
================================
Generates three focused HTML security reports from pipeline scan results:

  security-report.html  — Executive summary (all audiences)
  semgrep-detail.html   — Full Semgrep findings (security team + developers)
  dc-report-full.html   — Full CVE list (copied from Dependency-Check output)

Usage:
  Set environment variables before running (done automatically by Jenkinsfile):
    APP_NAME, GITLAB_REPO_PATH, APP_COMMIT, GIT_BRANCH, BUILD_NUMBER,
    BUILD_URL, SONAR_HOST, SONAR_TOKEN, PIPELINE_STATUS,
    PIPELINE_FAIL_REASON, WORKSPACE

  python3 generate-report.py

Requirements:
  Standard library only — no external dependencies required.
  SonarQube findings fetched via curl subprocess call.
"""

import json
import sys
import os
import subprocess
import shutil
from datetime import datetime
from pathlib import Path

# ── Environment ────────────────────────────────────────────────────────────────
APP_NAME         = os.environ.get('APP_NAME', 'unknown')
GITLAB_REPO_PATH = os.environ.get('GITLAB_REPO_PATH', 'unknown')
APP_COMMIT       = os.environ.get('APP_COMMIT', 'unknown')
GIT_BRANCH       = os.environ.get('GIT_BRANCH', 'unknown')
BUILD_NUMBER     = os.environ.get('BUILD_NUMBER', 'unknown')
BUILD_URL        = os.environ.get('BUILD_URL', '#')
SONAR_HOST       = os.environ.get('SONAR_HOST', '')
SONAR_TOKEN      = os.environ.get('SONAR_TOKEN', '')
PIPELINE_STATUS  = os.environ.get('PIPELINE_STATUS', 'UNKNOWN')
PIPELINE_REASON  = os.environ.get('PIPELINE_FAIL_REASON', '')
WORKSPACE        = os.environ.get('WORKSPACE', '.')

NOW = datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')


# ── Data loaders ───────────────────────────────────────────────────────────────

def load_semgrep():
    """Load Semgrep findings from workspace JSON report."""
    path = Path(WORKSPACE) / 'semgrep-report.json'
    if not path.exists():
        print("  Warning: semgrep-report.json not found", file=sys.stderr)
        return []
    try:
        return json.loads(path.read_text()).get('results', [])
    except Exception as e:
        print(f"  Warning: could not read semgrep-report.json: {e}", file=sys.stderr)
        return []


def load_dc():
    """Load Dependency-Check findings from workspace JSON report."""
    path = Path(WORKSPACE) / 'dc-report.json'
    if not path.exists():
        print("  Warning: dc-report.json not found", file=sys.stderr)
        return [], {}
    try:
        data   = json.loads(path.read_text())
        deps   = data.get('dependencies', [])
        counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        vulns  = []
        for d in deps:
            for v in d.get('vulnerabilities', []):
                sev = v.get('severity', 'UNKNOWN').upper()
                if sev in counts:
                    counts[sev] += 1
                vulns.append({
                    'cve':      v.get('name', 'N/A'),
                    'severity': sev,
                    'package':  d.get('fileName', 'unknown'),
                    'cvss':     v.get('cvssv3', {}).get('baseScore',
                                v.get('cvssv2', {}).get('score', 'N/A')),
                    'desc':     v.get('description', '')[:200],
                })
        # Sort by severity
        order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']
        vulns.sort(key=lambda x: order.index(x['severity'])
                   if x['severity'] in order else 99)
        return vulns, counts
    except Exception as e:
        print(f"  Warning: could not read dc-report.json: {e}", file=sys.stderr)
        return [], {}


def load_sonar():
    """Fetch SonarQube hotspots and vulnerabilities via API."""
    if not SONAR_HOST or not SONAR_TOKEN:
        print("  SonarQube credentials not set — skipping API call", file=sys.stderr)
        return [], []
    try:
        def sq(path):
            result = subprocess.run(
                ['curl', '-s', '-u', f'{SONAR_TOKEN}:', f'{SONAR_HOST}{path}'],
                capture_output=True, text=True, timeout=15
            )
            return json.loads(result.stdout)

        hotspots = sq(
            f"/api/hotspots/search?projectKey={APP_NAME}&status=TO_REVIEW"
        ).get('hotspots', [])

        vulns = sq(
            f"/api/issues/search?projectKeys={APP_NAME}&types=VULNERABILITY&resolved=false"
        ).get('issues', [])

        return hotspots, vulns
    except Exception as e:
        print(f"  Warning: SonarQube API error: {e}", file=sys.stderr)
        return [], []


# ── HTML helpers ───────────────────────────────────────────────────────────────

BASE_CSS = """
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: Arial, sans-serif; font-size: 14px; color: #404040;
       background: #F8F9FA; line-height: 1.6; }
.container { max-width: 1100px; margin: 0 auto; padding: 24px; }
.header { background: #1F4E79; color: white; padding: 28px 32px;
          border-radius: 8px; margin-bottom: 20px; }
.header h1 { font-size: 26px; font-weight: 700; }
.header .sub { font-size: 13px; opacity: 0.85; margin-top: 4px; }
.meta { display: grid; grid-template-columns: repeat(3,1fr);
        gap: 8px; margin-top: 16px; }
.meta-item { background: rgba(255,255,255,0.1); padding: 8px 12px;
             border-radius: 4px; }
.meta-item .label { font-size: 11px; text-transform: uppercase; opacity: 0.7; }
.meta-item .value { font-weight: 600; font-size: 13px; word-break: break-all; }
.status-bar { padding: 14px 20px; border-radius: 8px; margin-bottom: 20px;
              display: flex; align-items: center; gap: 16px; }
.status-bar .s-label { font-size: 20px; font-weight: 700; }
.status-bar .s-reason { font-size: 13px; color: #595959; }
.grid4 { display: grid; grid-template-columns: repeat(4,1fr);
         gap: 16px; margin-bottom: 20px; }
.card { background: white; border-radius: 8px; padding: 20px;
        text-align: center; border: 1px solid #E0E0E0; }
.card .count { font-size: 36px; font-weight: 700; }
.card .label { font-size: 12px; color: #595959; text-transform: uppercase;
               margin-top: 4px; }
.card.critical .count { color: #7B1F1F; }
.card.high     .count { color: #7B3F00; }
.card.medium   .count { color: #7B4F00; }
.card.info     .count { color: #1F4E79; }
.section { background: white; border-radius: 8px; padding: 24px;
           margin-bottom: 20px; border: 1px solid #E0E0E0; }
.section h2 { font-size: 18px; font-weight: 600; color: #1F4E79;
              padding-bottom: 10px; border-bottom: 2px solid #D6E4F0;
              margin-bottom: 14px; }
.section h3 { font-size: 14px; font-weight: 600; color: #595959;
              margin: 16px 0 8px; }
.tool-grid { display: grid; grid-template-columns: repeat(3,1fr); gap: 12px; }
.tool-card { border: 1px solid #E0E0E0; border-radius: 6px; padding: 16px; }
.tool-card h3 { font-size: 14px; font-weight: 600; color: #2E75B6;
                margin: 0 0 10px; }
.tool-card .row { font-size: 13px; color: #595959; margin: 3px 0; }
.link-btn { display: inline-block; margin-top: 10px; padding: 6px 14px;
            background: #EBF3FA; color: #1F4E79; border-radius: 4px;
            font-size: 12px; font-weight: 600; text-decoration: none; }
.link-btn:hover { background: #D6E4F0; }
table { width: 100%; border-collapse: collapse; font-size: 13px; }
th { background: #EBF3FA; color: #1F4E79; font-weight: 600;
     padding: 10px 12px; text-align: left; border-bottom: 2px solid #D6E4F0; }
td { padding: 9px 12px; border-bottom: 1px solid #F0F0F0; vertical-align: top; }
tr:last-child td { border-bottom: none; }
tr:hover td { background: #FAFAFA; }
.mono { font-family: monospace; font-size: 12px; }
.desc { color: #595959; font-size: 12px; }
.pill { background: #EBF3FA; color: #1F4E79; padding: 2px 8px;
        border-radius: 10px; font-size: 11px; font-weight: 600; }
.badge { padding: 2px 8px; border-radius: 4px;
         font-size: 12px; font-weight: 600; }
.empty { color: #888; font-style: italic; padding: 20px; text-align: center; }
.footer { text-align: center; font-size: 12px; color: #888;
          margin-top: 20px; padding: 16px; }
a { color: #2E75B6; text-decoration: none; }
a:hover { text-decoration: underline; }
@media print { body { background: white; } .container { padding: 0; } }
"""

BADGE_COLORS = {
    'CRITICAL': ('#7B1F1F', '#FDECEA'),
    'HIGH':     ('#7B3F00', '#FFF0E0'),
    'MEDIUM':   ('#7B4F00', '#FFF3CD'),
    'LOW':      ('#1D6B5E', '#E1F5EE'),
    'ERROR':    ('#7B1F1F', '#FDECEA'),
    'WARNING':  ('#7B4F00', '#FFF3CD'),
}


def badge(sev):
    c = BADGE_COLORS.get(sev.upper(), ('#404040', '#F2F2F2'))
    return (f'<span class="badge" '
            f'style="background:{c[1]};color:{c[0]};">{sev}</span>')


def page_head(title):
    return (f'<!DOCTYPE html>\n<html lang="en">\n<head>\n'
            f'<meta charset="UTF-8">\n'
            f'<meta name="viewport" content="width=device-width,initial-scale=1">\n'
            f'<title>{title}</title>\n'
            f'<style>{BASE_CSS}</style>\n</head>\n<body>\n<div class="container">\n')


def page_header(title, subtitle):
    return f"""
  <div class="header">
    <h1>{title}</h1>
    <div class="sub">{subtitle}</div>
    <div class="meta">
      <div class="meta-item">
        <div class="label">Repository</div>
        <div class="value">{GITLAB_REPO_PATH}</div>
      </div>
      <div class="meta-item">
        <div class="label">Branch</div>
        <div class="value">{GIT_BRANCH}</div>
      </div>
      <div class="meta-item">
        <div class="label">Commit</div>
        <div class="value">{APP_COMMIT[:12]}</div>
      </div>
      <div class="meta-item">
        <div class="label">Build</div>
        <div class="value">#{BUILD_NUMBER}</div>
      </div>
      <div class="meta-item">
        <div class="label">Scan date</div>
        <div class="value">{NOW}</div>
      </div>
      <div class="meta-item">
        <div class="label">Jenkins</div>
        <div class="value">
          <a href="{BUILD_URL}" style="color:rgba(255,255,255,0.9);">
            Build #{BUILD_NUMBER}
          </a>
        </div>
      </div>
    </div>
  </div>
"""


def status_bar():
    passed = PIPELINE_STATUS == 'PASSED'
    bg     = '#D4EDDA' if passed else '#FDECEA'
    border = '#1E5631' if passed else '#7B1F1F'
    color  = '#1E5631' if passed else '#7B1F1F'
    label  = 'PASSED ✅' if passed else 'FAILED ❌'
    reason = '' if passed else PIPELINE_REASON
    return (f'<div class="status-bar" '
            f'style="background:{bg};border-left:6px solid {border};">\n'
            f'  <div class="s-label" style="color:{color};">{label}</div>\n'
            f'  <div class="s-reason">'
            f'{"All security checks passed." if not reason else reason}'
            f'</div>\n</div>\n')


def page_footer():
    return (f'\n  <div class="footer">'
            f'Generated automatically by the Jenkins security pipeline'
            f' &nbsp;·&nbsp; '
            f'<a href="{BUILD_URL}">Build #{BUILD_NUMBER}</a>'
            f' &nbsp;·&nbsp; {NOW}'
            f'</div>\n</div>\n</body>\n</html>')


# ── Report 1: Executive summary ────────────────────────────────────────────────

def generate_summary(semgrep, dc_vulns, dc_counts, hotspots, sq_vulns):
    sg_errors = len([f for f in semgrep
                     if f.get('extra', {}).get('severity') == 'ERROR'])
    sg_warns  = len([f for f in semgrep
                     if f.get('extra', {}).get('severity') == 'WARNING'])
    total_blocking = (sg_errors
                      + dc_counts.get('CRITICAL', 0)
                      + dc_counts.get('HIGH', 0))

    sq_status = 'PASSED' if PIPELINE_STATUS == 'PASSED' else 'FAILED'
    sq_color  = '#1E5631' if sq_status == 'PASSED' else '#7B1F1F'

    html  = page_head(f"Security Report — {APP_NAME}")
    html += page_header(f"Security Scan Report — {APP_NAME}",
                        "Executive summary")
    html += status_bar()

    # Summary cards
    html += f"""
  <div class="grid4">
    <div class="card critical">
      <div class="count">{dc_counts.get('CRITICAL', 0)}</div>
      <div class="label">Critical CVEs</div>
    </div>
    <div class="card high">
      <div class="count">{dc_counts.get('HIGH', 0)}</div>
      <div class="label">High CVEs</div>
    </div>
    <div class="card medium">
      <div class="count">{dc_counts.get('MEDIUM', 0) + sg_warns}</div>
      <div class="label">Medium findings</div>
    </div>
    <div class="card info">
      <div class="count">{total_blocking}</div>
      <div class="label">Blocking pipeline</div>
    </div>
  </div>
"""

    # Tool summary
    html += """
  <div class="section">
    <h2>Tool results</h2>
    <div class="tool-grid">
"""
    html += f"""
      <div class="tool-card">
        <h3>Semgrep SAST</h3>
        <div class="row">{badge('ERROR')} {sg_errors} blocking</div>
        <div class="row">{badge('WARNING')} {sg_warns} warnings</div>
        <div class="row" style="margin-top:6px;color:#888;">
          {len(semgrep)} total findings
        </div>
        <a class="link-btn" href="semgrep-detail.html">View full findings</a>
      </div>
      <div class="tool-card">
        <h3>Dependency-Check SCA</h3>
        <div class="row">{badge('CRITICAL')} {dc_counts.get('CRITICAL', 0)} critical</div>
        <div class="row">{badge('HIGH')} {dc_counts.get('HIGH', 0)} high</div>
        <div class="row">{badge('MEDIUM')} {dc_counts.get('MEDIUM', 0)} medium</div>
        <div class="row" style="margin-top:6px;color:#888;">
          {len(dc_vulns)} total CVEs
        </div>
        <a class="link-btn" href="dc-report-full.html">View full CVE report</a>
      </div>
      <div class="tool-card">
        <h3>SonarQube SAST</h3>
        <div class="row">{badge('HIGH')} {len(hotspots)} hotspots unreviewed</div>
        <div class="row">{badge('MEDIUM')} {len(sq_vulns)} vulnerabilities</div>
        <div class="row" style="margin-top:6px;">
          Quality Gate:
          <strong style="color:{sq_color};">{sq_status}</strong>
        </div>
        <a class="link-btn"
           href="{SONAR_HOST}/dashboard?id={APP_NAME}" target="_blank">
          View SonarQube dashboard
        </a>
      </div>
    </div>
  </div>
"""

    # Scan metadata
    html += f"""
  <div class="section">
    <h2>Scan metadata</h2>
    <table>
      <tr><th style="width:220px;">Item</th><th>Value</th></tr>
      <tr><td>Project</td><td>{APP_NAME}</td></tr>
      <tr><td>Repository</td><td>{GITLAB_REPO_PATH}</td></tr>
      <tr><td>Commit SHA</td>
          <td class="mono">{APP_COMMIT}</td></tr>
      <tr><td>Branch</td><td>{GIT_BRANCH}</td></tr>
      <tr><td>Scan date</td><td>{NOW}</td></tr>
      <tr><td>Jenkins build</td>
          <td>#{BUILD_NUMBER} &nbsp;
          <a href="{BUILD_URL}">{BUILD_URL}</a></td></tr>
      <tr><td>Pipeline status</td><td>{PIPELINE_STATUS}</td></tr>
      <tr><td>Semgrep rulesets</td>
          <td>p/php &nbsp;·&nbsp; p/csharp &nbsp;·&nbsp;
              p/owasp-top-ten &nbsp;·&nbsp; p/security-audit</td></tr>
      <tr><td>Dependency-Check</td>
          <td>v12.x &nbsp;·&nbsp; NVD database (updated daily)</td></tr>
      <tr><td>SonarQube</td>
          <td>v10.x &nbsp;·&nbsp; Quality Gate: Security Gate</td></tr>
    </table>
  </div>
"""

    html += page_footer()
    return html


# ── Report 2: Semgrep detail ───────────────────────────────────────────────────

def generate_semgrep_detail(semgrep):
    errors   = [f for f in semgrep
                if f.get('extra', {}).get('severity') == 'ERROR']
    warnings = [f for f in semgrep
                if f.get('extra', {}).get('severity') == 'WARNING']

    html  = page_head(f"Semgrep Findings — {APP_NAME}")
    html += page_header(
        f"Semgrep SAST Findings — {APP_NAME}",
        f"{len(errors)} blocking &nbsp;·&nbsp; "
        f"{len(warnings)} warnings &nbsp;·&nbsp; "
        f"{len(semgrep)} total"
    )
    html += status_bar()

    def findings_table(findings, title, sev):
        if not findings:
            return (f'<p class="empty">No {title.lower()}</p>')
        out = f'<h3>{title} — {len(findings)}</h3>\n'
        out += ('<table>\n<tr>'
                '<th style="width:90px;">Severity</th>'
                '<th>File</th>'
                '<th style="width:60px;">Line</th>'
                '<th style="width:160px;">Rule</th>'
                '<th>Description</th></tr>\n')
        for f in findings:
            path = f.get('path', 'unknown')
            line = f.get('start', {}).get('line', '-')
            rule = f.get('check_id', '').split('.')[-1]
            msg  = f.get('extra', {}).get('message',
                   f.get('check_id', ''))[:200]
            out += (f'<tr>'
                    f'<td>{badge(sev)}</td>'
                    f'<td class="mono">{path}</td>'
                    f'<td>{line}</td>'
                    f'<td><span class="pill">{rule[:30]}</span></td>'
                    f'<td class="desc">{msg}</td>'
                    f'</tr>\n')
        out += '</table>\n'
        return out

    html += '<div class="section"><h2>Findings</h2>\n'
    html += findings_table(errors, "Blocking findings (ERROR)", "ERROR")
    html += findings_table(warnings, "Warnings", "WARNING")
    html += '</div>\n'
    html += page_footer()
    return html


# ── Main ───────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    ws = Path(WORKSPACE)

    print("Loading Semgrep findings...")
    semgrep = load_semgrep()
    print(f"  {len(semgrep)} findings")

    print("Loading Dependency-Check findings...")
    dc_vulns, dc_counts = load_dc()
    print(f"  {len(dc_vulns)} CVEs — "
          f"CRITICAL: {dc_counts.get('CRITICAL', 0)} "
          f"HIGH: {dc_counts.get('HIGH', 0)} "
          f"MEDIUM: {dc_counts.get('MEDIUM', 0)}")

    print("Loading SonarQube findings...")
    hotspots, sq_vulns = load_sonar()
    print(f"  {len(hotspots)} hotspots, {len(sq_vulns)} vulnerabilities")

    print("Generating security-report.html (summary)...")
    (ws / 'security-report.html').write_text(
        generate_summary(semgrep, dc_vulns, dc_counts, hotspots, sq_vulns),
        encoding='utf-8'
    )

    print("Generating semgrep-detail.html...")
    (ws / 'semgrep-detail.html').write_text(
        generate_semgrep_detail(semgrep),
        encoding='utf-8'
    )

    print("Copying Dependency-Check HTML report...")
    dc_html = Path('/tmp/dc-report/dependency-check-report.html')
    if dc_html.exists():
        shutil.copy(dc_html, ws / 'dc-report-full.html')
        print("  Copied dc-report-full.html")
    else:
        print("  Warning: dc-report-full.html not found at /tmp/dc-report/",
              file=sys.stderr)

    print("Done.")
    print(f"  {ws}/security-report.html")
    print(f"  {ws}/semgrep-detail.html")
    print(f"  {ws}/dc-report-full.html")
