# Onboarding a New Project

Three steps, approximately 10 minutes per repository.

## Prerequisites

- Jenkins, SonarQube, and all tools installed and running
- Jenkins credentials configured (see [jenkins-setup.md](jenkins-setup.md))
- GitLab repository exists and has at least one commit on `main`

---

## Step 1 — Create the SonarQube project (2 min)

1. Navigate to `http://<sonarqube-ip>:9000`
2. **Projects → Create project → Manually**
3. Set **Project display name**: use the repository name
4. Set **Project key**: use the **exact** repository name (case-sensitive)
5. Set **Main branch name**: `main`
6. Click **Create project** — ignore the scanner setup instructions

> ⚠️ The project key must match **exactly** the value you will use for `APP_NAME` in the Jenkins job. A single character difference will cause the pipeline to analyse the wrong project.

---

## Step 2 — Create the Jenkins pipeline job (5 min)

### 2a — Create the item

1. Navigate to `http://<jenkins-ip>:8080`
2. **New Item** → enter name = exact repository name → **Pipeline** → **OK**

### 2b — Add the three required parameters

In **General** → tick **This project is parameterised** → **Add Parameter → String Parameter** (three times):

| Name | Default value | Description |
|---|---|---|
| `APP_NAME` | exact SonarQube project key | Must match exactly — case-sensitive |
| `GITLAB_PROJECT_ID` | numeric ID from GitLab | Settings → General → Project ID |
| `GITLAB_REPO_PATH` | `group/repo-name` | Path portion of the GitLab URL |

### 2c — Configure the Pipeline section

| Field | Value |
|---|---|
| Definition | Pipeline script from SCM |
| SCM | Git |
| Repository URL | `http://<gitlab-ip>/security-pipeline/security-pipeline.git` |
| Credentials | `security-group-token` |
| Branch specifier | `*/main` |
| Script path | `Jenkinsfile` |

Click **Save**.

### 2d — Run once to activate the webhook trigger

1. Click **Build with Parameters**
2. Verify all three parameter values are correct
3. Click **Build**
4. Wait for the build to complete — confirm no configuration errors in the log

---

## Step 3 — Add the GitLab webhook (2 min)

1. Navigate to the application repository in GitLab
2. **Settings → Webhooks → Add new webhook**

| Field | Value |
|---|---|
| URL | `http://<jenkins-ip>:8080/project/<job-name>` |
| Secret token | value from Jenkins credential `gitlab-webhook-secret` |
| Push events | ✅ enabled |
| Merge request events | ✅ enabled |
| SSL verification | disable if Jenkins has no TLS certificate |

3. Click **Add webhook**
4. Click **Test → Push events** — verify **HTTP 200** response
5. Verify a new build appears in Jenkins triggered by the test

---

## Post-integration verification checklist

- [ ] Jenkinsfile fetched from `security-pipeline/security-pipeline` (line 1 of Jenkins log)
- [ ] Application code checked out from correct repository
- [ ] `APP_COMMIT` matches a commit in the application repo (not the pipeline repo)
- [ ] Semgrep scans application files (check file count in log)
- [ ] Dependency-Check analyses `composer.lock` or `packages.lock.json`
- [ ] SonarQube results appear under the correct project key
- [ ] GitLab commit comments posted to the correct commit
- [ ] Three HTML reports visible in Jenkins build artifacts

---

## Dependency lock file requirement

Dependency-Check requires the lock file to be committed:

| Language | Required file | Generate with |
|---|---|---|
| PHP / Composer | `composer.lock` | `composer install` |
| .NET / NuGet | `packages.lock.json` | `dotnet restore --use-lock-file` |
| Node.js / npm | `package-lock.json` | `npm install` |
| Node.js / Yarn | `yarn.lock` | `yarn install` |
