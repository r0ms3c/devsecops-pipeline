# Jenkins Credentials Setup

All credentials are stored in **Jenkins → Manage Jenkins → Credentials → System → Global credentials**.

## Required credentials

| Credential ID | Kind | Purpose | Risk |
|---|---|---|---|
| `jenkins-ci-checkout` | Username/password | Checkout application repositories | ⚠️ HIGH — use service account |
| `security-group-token` | Username/password | Checkout security-pipeline repo | LOW |
| `gitlab-api-token` | Secret text | Post commit comments to GitLab | LOW |
| `sonarqube-token` | Secret text | Send analysis results to SonarQube | LOW |
| `sonarqube-read-token` | Secret text | Read SonarQube results for reports | LOW |
| `nvd-api-key` | Secret text | NVD database daily updates | LOW |
| `gitlab-webhook-secret` | Secret text | Verify webhook signatures | LOW |

---

## Creating each credential

### `jenkins-ci-checkout`

This credential checks out application repositories during pipeline runs.

> ⚠️ **Important:** This should be a **dedicated service account** in GitLab, not a personal account. See the [account recommendations](#account-recommendations) section below.

1. Create a GitLab Personal Access Token for the service account with scope: `read_repository`
2. In Jenkins: **Add Credentials → Username with password**
   - Username: GitLab service account username
   - Password: the Personal Access Token
   - ID: `jenkins-ci-checkout`

### `security-group-token`

This credential checks out the security-pipeline repository itself.

1. In GitLab: **security-pipeline group → Settings → Access Tokens**
   - Token name: `jenkins-security-pipeline`
   - Role: Developer
   - Scopes: `read_repository`
2. In Jenkins: **Add Credentials → Username with password**
   - Username: `oauth2`
   - Password: the Group Access Token
   - ID: `security-group-token`

### `gitlab-api-token`

Used to post security findings as commit comments.

1. In GitLab: **User Settings → Access Tokens**
   - Name: `jenkins-api`
   - Scopes: `api`
2. In Jenkins: **Add Credentials → Secret text**
   - Secret: the token value
   - ID: `gitlab-api-token`

### `sonarqube-token` and `sonarqube-read-token`

Two separate tokens — one for writing analysis results, one for reading them.

1. In SonarQube: **My Account → Security → Generate Tokens**
   - Generate `jenkins-analysis` (User token) — used for analysis
   - Generate `jenkins-report-reader` (User token) — used for reading results
2. In Jenkins: create two **Secret text** credentials:
   - ID: `sonarqube-token` → `jenkins-analysis` token
   - ID: `sonarqube-read-token` → `jenkins-report-reader` token

### `nvd-api-key`

Free API key from NIST for NVD database updates.

1. Request a key at: https://nvd.nist.gov/developers/request-an-api-key
2. In Jenkins: **Add Credentials → Secret text**
   - Secret: the API key
   - ID: `nvd-api-key`

### `gitlab-webhook-secret`

A shared secret used to verify that webhook requests come from GitLab.

1. Generate a random string: `openssl rand -hex 32`
2. In Jenkins: **Add Credentials → Secret text**
   - Secret: the generated string
   - ID: `gitlab-webhook-secret`
3. Use this same value when configuring webhooks in GitLab

---

## Credential rotation schedule

| Credential | Rotate every |
|---|---|
| `jenkins-ci-checkout` | 90 days |
| `gitlab-api-token` | 90 days |
| `security-group-token` | 90 days |
| `gitlab-webhook-secret` | 180 days |
| `sonarqube-token` | 180 days |
| `sonarqube-read-token` | 180 days |
| `nvd-api-key` | Annually |

---

## Account recommendations

### Current risk: `jenkins-ci-checkout`

If `jenkins-ci-checkout` is tied to a personal account, the pipeline breaks when that person leaves the organisation. This is a **HIGH** risk item.

**Recommended fix:**
1. Ask IT to provision `svc_jenkins_ci` in Active Directory under the service accounts OU
2. Ask the GitLab administrator to include the service accounts OU in the GitLab LDAP scope
3. Create a GitLab account for `svc_jenkins_ci` and generate a Personal Access Token
4. Update the `jenkins-ci-checkout` credential with the service account token

### SonarQube also needs permissions

The `sonarqube-read-token` user must have **Browse** permission on each SonarQube project to read hotspots and vulnerabilities via the API. Grant this in:

**SonarQube → Project → Project Settings → Permissions → Add user → Browse**
