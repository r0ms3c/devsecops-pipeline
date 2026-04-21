# Pipeline Architecture

## Overview

This pipeline implements a **shared security pipeline** pattern — a single `Jenkinsfile` maintained by the security team is used by all application repositories. Developers never modify pipeline logic.

```
┌─────────────────────────────────────────────────────────────────┐
│                        Bank Internal Network                    │
│                                                                 │
│  ┌──────────┐    webhook    ┌──────────┐    analysis    ┌─────┐ │
│  │  GitLab  │ ────────────▶ │ Jenkins  │ ─────────────▶ │ SQ  │ │
│  │          │ ◀──────────── │          │ ◀───────────── │     │ │
│  │ commit   │   comments    │  + tools │   quality gate └─────┘ │
│  │ status   │               │          │                        │
│  └──────────┘               └──────────┘                        │
│                               │    │    │                       │
│                            Semgrep DC  SonarQube                │
│                            Scanner    Scanner                   │
│                                                                 │
│                          ┌──────────┐                           │
│                          │   NVD    │                           │
│                          │ Database │ (local cache, daily sync) │
│                          └──────────┘                           │
└─────────────────────────────────────────────────────────────────┘
```

## Components

| Component | Role | Version |
|---|---|---|
| GitLab | Source control + webhook trigger | CE |
| Jenkins | Pipeline orchestration | LTS |
| Semgrep | SAST — code pattern analysis | 1.x |
| Dependency-Check | SCA — library CVE scanning | 12.x |
| SonarQube | SAST — deep analysis + quality gate | 10.x CE |
| NVD Database | Local CVE cache for Dependency-Check | Updated daily |

## Shared pipeline design

```
security-pipeline/
└── security-pipeline/      ← this repository
    ├── Jenkinsfile          ← ALL application jobs point here
    └── generate-report.py

application-repo-one/
└── Jenkinsfile             ← 3-line comment only, no logic

application-repo-two/
└── Jenkinsfile             ← 3-line comment only, no logic
```

**Why this matters:** When the security team needs to update a rule, add a tool, or fix a bug, they commit to one file and it applies to every project on their next push. No coordination with development teams required.

## Pipeline stages

```
Validate configuration
        │
Checkout application code
        │
Semgrep SAST ──────────────────┐
        │                      │
Dependency-Check SCA ──────────┤ findings posted as
        │                      │ GitLab commit comments
SonarQube analysis ────────────┤
        │                      │
Quality Gate ──────────────────┘
        │
Generate security reports
  ├── security-report.html   (executive summary)
  ├── semgrep-detail.html    (full Semgrep findings)
  └── dc-report-full.html    (full CVE list)
        │
Security Gate
  ├── PASSED → green commit status in GitLab
  └── FAILED → red commit status + combined failure reason
```

## All stages always run

All stages run regardless of earlier findings. The Security Gate at the end fails with a combined reason that includes all tools. This ensures:
- Developers see all issues in one push, not one per push
- Security team gets a complete picture in every run
- HTML reports are always generated even on failure

## Storage management

| Artifact | Size | Policy |
|---|---|---|
| `semgrep-report.json` | ~50 KB | Archived per build |
| `security-report.html` | ~100 KB | Archived per build |
| `semgrep-detail.html` | ~50 KB | Archived per build |
| `dc-report-full.html` | ~500 KB | Archived per build |
| `dc-report.json` | ~19 MB | **Not archived** — too large |

Jenkins retention: last 50 builds or 30 days per job.
