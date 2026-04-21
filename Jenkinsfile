// ============================================================================
// DevSecOps Security Pipeline
// Maintained by the Security Team — security-pipeline/security-pipeline
//
// This Jenkinsfile is fetched centrally from this repository.
// Application repositories contain only a 3-line comment Jenkinsfile.
//
// Required Jenkins job parameters:
//   APP_NAME          — SonarQube project key (must match exactly)
//   GITLAB_PROJECT_ID — Numeric GitLab project ID
//   GITLAB_REPO_PATH  — Repository path e.g. group/repo-name
//
// Required Jenkins credentials:
//   jenkins-ci-checkout    — Username/password for application repo checkout
//   security-group-token   — Group Access Token for this pipeline repo
//   gitlab-api-token       — GitLab API token for posting commit comments
//   sonarqube-token        — SonarQube analysis token
//   sonarqube-read-token   — SonarQube read token for report generation
//   nvd-api-key            — NVD API key for Dependency-Check database updates
// ============================================================================

pipeline {
    agent any

    triggers {
        gitlab(
            triggerOnPush: true,
            triggerOnMergeRequest: true
        )
    }

    environment {
        // ── Server addresses — update these for your environment ──────────────
        SONAR_HOST  = 'http://<sonarqube-ip>:9000'
        GITLAB_HOST = 'http://<gitlab-ip>'
        DC_HOME     = '/opt/dependency-check/bin/dependency-check.sh'
    }

    stages {

        stage('Validate configuration') {
            steps {
                script {
                    if (!env.APP_NAME) {
                        error "APP_NAME is not set in this Jenkins job. " +
                              "Go to job Configure → This project is parameterized and add APP_NAME."
                    }
                    if (!env.GITLAB_PROJECT_ID) {
                        error "GITLAB_PROJECT_ID is not set in this Jenkins job."
                    }
                    if (!env.GITLAB_REPO_PATH) {
                        error "GITLAB_REPO_PATH is not set in this Jenkins job."
                    }
                    echo "Running security pipeline for: ${env.APP_NAME}"
                    echo "GitLab project ID: ${env.GITLAB_PROJECT_ID}"
                    echo "Repository path: ${env.GITLAB_REPO_PATH}"
                }
            }
        }

        stage('Checkout application code') {
            steps {
                script {
                    // Save the report generator before workspace is overwritten
                    sh 'cp generate-report.py /tmp/generate-report.py'

                    checkout([
                        $class: 'GitSCM',
                        branches: [[name: '*/main']],
                        userRemoteConfigs: [[
                            url: "${env.GITLAB_HOST}/${env.GITLAB_REPO_PATH}.git",
                            credentialsId: 'jenkins-ci-checkout'
                        ]]
                    ])

                    env.APP_COMMIT = sh(
                        script: 'git rev-parse HEAD',
                        returnStdout: true
                    ).trim()
                    echo "Application commit: ${env.APP_COMMIT}"
                }
            }
        }

        stage('Semgrep SAST') {
            steps {
                script {
                    // Clean up any leftover files from previous runs
                    sh 'rm -f semgrep-report.json dc-report.json security-report.html semgrep-detail.html dc-report-full.html comment-body.txt gitlab-comment.json || true'

                    sh '''
                        semgrep \
                          --config=p/php \
                          --config=p/csharp \
                          --config=p/owasp-top-ten \
                          --config=p/security-audit \
                          --severity=WARNING \
                          --severity=ERROR \
                          --json \
                          --output=/tmp/semgrep-report.json \
                          . || true
                    '''

                    // Also run any custom bank-specific rules if they exist
                    sh '''
                        if [ -f /tmp/generate-report.py ]; then
                            if [ -d /var/lib/jenkins/custom-rules ]; then
                                semgrep \
                                  --config=/var/lib/jenkins/custom-rules \
                                  --json \
                                  --output=/tmp/semgrep-custom.json \
                                  . || true
                            fi
                        fi
                    '''

                    def reportContent = sh(
                        script: 'cat /tmp/semgrep-report.json',
                        returnStdout: true
                    ).trim()
                    writeFile file: 'semgrep-report.json', text: reportContent
                    archiveArtifacts artifacts: 'semgrep-report.json', allowEmptyArchive: true

                    def semgrepJson  = readJSON file: 'semgrep-report.json'
                    def findings     = semgrepJson.results ?: []
                    def errorCount   = findings.count { it.extra?.severity == 'ERROR' }
                    def warningCount = findings.count { it.extra?.severity == 'WARNING' }

                    echo "Semgrep — ERROR: ${errorCount} WARNING: ${warningCount}"

                    env.SEMGREP_ERRORS   = "${errorCount}"
                    env.SEMGREP_WARNINGS = "${warningCount}"
                    env.SEMGREP_TOTAL    = "${findings.size()}"

                    if (errorCount > 0 || warningCount > 0) {
                        postGitlabComment(buildSemgrepReport(findings))
                    }
                    if (errorCount > 0) {
                        env.PIPELINE_FAILED = 'true'
                        env.PIPELINE_FAIL_REASON = "Semgrep found ${errorCount} blocking security issue(s)."
                    }
                }
            }
        }

        stage('Dependency-Check SCA') {
            steps {
                script {
                    sh """
                        ${env.DC_HOME} \
                          --project "${env.APP_NAME}" \
                          --scan . \
                          --format JSON \
                          --format HTML \
                          --out /tmp/dc-report \
                          --noupdate \
                          --enableRetired \
                          --enableExperimental \
                          --failOnCVSS 7 || true
                    """

                    // Uncomment to use a suppression file for false positives:
                    // --suppression dc-suppressions.xml

                    def dcContent = sh(
                        script: 'cat /tmp/dc-report/dependency-check-report.json',
                        returnStdout: true
                    ).trim()
                    writeFile file: 'dc-report.json', text: dcContent

                    // dc-report.json is ~19MB — archiving disabled to save storage.
                    // The full CVE report is available as dc-report-full.html in artifacts.
                    // Uncomment the line below if you need the raw JSON:
                    // archiveArtifacts artifacts: 'dc-report.json', allowEmptyArchive: true

                    def dcJson    = readJSON file: 'dc-report.json'
                    def deps      = dcJson.dependencies ?: []
                    def critical  = 0
                    def high      = 0
                    def medium    = 0

                    deps.each { d ->
                        d.vulnerabilities?.each { v ->
                            def sev = v.severity?.toUpperCase() ?: ''
                            if (sev == 'CRITICAL')    critical++
                            else if (sev == 'HIGH')   high++
                            else if (sev == 'MEDIUM') medium++
                        }
                    }

                    echo "Dependency-Check — CRITICAL: ${critical} HIGH: ${high} MEDIUM: ${medium}"

                    env.DC_CRITICAL = "${critical}"
                    env.DC_HIGH     = "${high}"
                    env.DC_MEDIUM   = "${medium}"

                    if (critical > 0 || high > 0 || medium > 0) {
                        postGitlabComment(buildDcReport(deps))
                    }
                    if (critical > 0 || high > 0) {
                        env.PIPELINE_FAILED = 'true'
                        env.PIPELINE_FAIL_REASON = (env.PIPELINE_FAIL_REASON ? env.PIPELINE_FAIL_REASON + ' | ' : '') +
                            "Dependency-Check found ${critical} CRITICAL and ${high} HIGH vulnerabilities."
                    }
                }
            }
        }

        stage('SonarQube analysis') {
            steps {
                withSonarQubeEnv('SonarQube') {
                    sh """
                        sonar-scanner \
                          -Dsonar.projectKey=${env.APP_NAME} \
                          -Dsonar.sources=. \
                          -Dsonar.scm.revision=${env.APP_COMMIT} \
                          -Dsonar.exclusions=dc-report.json,semgrep-report.json,security-report.html,semgrep-detail.html,dc-report-full.html
                    """
                }
            }
        }

        stage('Quality Gate') {
            steps {
                script {
                    timeout(time: 5, unit: 'MINUTES') {
                        def qg = waitForQualityGate()
                        env.QUALITY_GATE_STATUS = qg.status
                        if (qg.status != 'OK') {
                            postGitlabComment(buildSonarReport())
                            env.PIPELINE_FAILED = 'true'
                            env.PIPELINE_FAIL_REASON = (env.PIPELINE_FAIL_REASON ? env.PIPELINE_FAIL_REASON + ' | ' : '') +
                                "SonarQube Quality Gate failed."
                        }
                    }
                }
            }
        }

        stage('Generate security report') {
            steps {
                script {
                    withCredentials([
                        string(credentialsId: 'sonarqube-token', variable: 'SONAR_TOKEN'),
                        string(credentialsId: 'sonarqube-read-token', variable: 'SONAR_READ_TOKEN')
                    ]) {
                        writeFile file: '/tmp/report-env.sh', text: """
export APP_NAME="${env.APP_NAME}"
export GITLAB_REPO_PATH="${env.GITLAB_REPO_PATH}"
export APP_COMMIT="${env.APP_COMMIT}"
export GIT_BRANCH="${env.GIT_BRANCH ?: 'main'}"
export BUILD_NUMBER="${env.BUILD_NUMBER}"
export BUILD_URL="${env.BUILD_URL}"
export SONAR_HOST="${env.SONAR_HOST}"
export SONAR_TOKEN="\${SONAR_READ_TOKEN}"
export PIPELINE_STATUS="${env.PIPELINE_FAILED == 'true' ? 'FAILED' : 'PASSED'}"
export WORKSPACE="${env.WORKSPACE}"
"""
                        writeFile file: '/tmp/report-reason.txt',
                                  text: env.PIPELINE_FAIL_REASON ?: ''

                        sh '''
                            . /tmp/report-env.sh
                            export PIPELINE_FAIL_REASON=$(cat /tmp/report-reason.txt)
                            python3 /tmp/generate-report.py
                            rm -f /tmp/report-env.sh /tmp/report-reason.txt
                        '''
                    }
                    archiveArtifacts artifacts: 'security-report.html,semgrep-detail.html,dc-report-full.html', allowEmptyArchive: true
                    echo "Reports archived — download from Jenkins build artifacts"
                }
            }
        }

        stage('Security Gate') {
            steps {
                script {
                    if (env.PIPELINE_FAILED == 'true') {
                        error "Pipeline failed: ${env.PIPELINE_FAIL_REASON}"
                    }
                }
            }
        }

    }

    post {
        success {
            script {
                def msg = "### Security Pipeline\n\n" +
                          "**Status: PASSED** ✅\n\n" +
                          "**Semgrep:** ${env.SEMGREP_TOTAL ?: 0} findings " +
                          "(${env.SEMGREP_ERRORS ?: 0} blocking, ${env.SEMGREP_WARNINGS ?: 0} warnings)\n\n" +
                          "**Dependency-Check:** CRITICAL: ${env.DC_CRITICAL ?: 0} " +
                          "HIGH: ${env.DC_HIGH ?: 0} MEDIUM: ${env.DC_MEDIUM ?: 0}\n\n" +
                          "**SonarQube Quality Gate:** PASSED\n\n" +
                          "[View SonarQube report](${env.SONAR_HOST}/dashboard?id=${env.APP_NAME})"
                postGitlabComment(msg)
            }
            updateGitlabCommitStatus name: 'ci/jenkins', state: 'success'
        }
        failure {
            updateGitlabCommitStatus name: 'ci/jenkins', state: 'failed'
        }
    }
}

// ── Helper: build Semgrep GitLab comment ─────────────────────────────────────
def buildSemgrepReport(List findings) {
    def errorList   = findings.findAll { it.extra?.severity == 'ERROR' }
    def warningList = findings.findAll { it.extra?.severity == 'WARNING' }
    def status      = errorList.size() > 0 ? 'FAILED' : 'WARNING'
    def message     = "### Semgrep SAST\n\n**Status: ${status}**\n\n"

    if (errorList.size() > 0) {
        message += "#### Blocking findings (ERROR) — ${errorList.size()}\n\n"
        errorList.take(10).each { f ->
            def path = f.path ?: 'unknown'
            def line = f.start?.line ?: '-'
            def msg  = f.extra?.message ?: f.check_id ?: 'Security issue'
            if (msg.length() > 100) msg = msg.take(100) + '...'
            message += "- **ERROR** | ${path} line ${line} | ${msg}\n"
        }
        message += "\n"
    }
    if (warningList.size() > 0) {
        message += "#### Warnings — ${warningList.size()}\n\n"
        warningList.take(5).each { f ->
            def path = f.path ?: 'unknown'
            def line = f.start?.line ?: '-'
            def msg  = f.extra?.message ?: f.check_id ?: 'Security issue'
            if (msg.length() > 100) msg = msg.take(100) + '...'
            message += "- **WARNING** | ${path} line ${line} | ${msg}\n"
        }
        message += "\n"
    }
    message += "---\n_Fix blocking findings before pipeline can pass._"
    return message
}

// ── Helper: build Dependency-Check GitLab comment ────────────────────────────
def buildDcReport(List deps) {
    def critical = []
    def high     = []
    def medium   = []

    deps.each { d ->
        d.vulnerabilities?.each { v ->
            def sev   = v.severity?.toUpperCase() ?: ''
            def entry = "**${v.name ?: 'CVE-?'}** | ${d.fileName ?: 'unknown'} | ${(v.description ?: '').take(80)}..."
            if (sev == 'CRITICAL')    critical << entry
            else if (sev == 'HIGH')   high << entry
            else if (sev == 'MEDIUM') medium << entry
        }
    }

    def status  = (critical.size() > 0 || high.size() > 0) ? 'FAILED' : 'WARNING'
    def message = "### Dependency-Check SCA\n\n**Status: ${status}**\n\n"

    if (critical.size() > 0) {
        message += "#### Critical vulnerabilities — ${critical.size()}\n\n"
        critical.take(5).each { message += "- ${it}\n" }
        if (critical.size() > 5) message += "- _...and ${critical.size() - 5} more_\n"
        message += "\n"
    }
    if (high.size() > 0) {
        message += "#### High vulnerabilities — ${high.size()}\n\n"
        high.take(5).each { message += "- ${it}\n" }
        if (high.size() > 5) message += "- _...and ${high.size() - 5} more_\n"
        message += "\n"
    }
    if (medium.size() > 0) {
        message += "#### Medium vulnerabilities — ${medium.size()}\n\n"
        medium.take(3).each { message += "- ${it}\n" }
        if (medium.size() > 3) message += "- _...and ${medium.size() - 3} more_\n"
        message += "\n"
    }

    message += "---\n_Update affected dependencies to resolve vulnerabilities._"
    return message
}

// ── Helper: build SonarQube GitLab comment ───────────────────────────────────
def buildSonarReport() {
    def sonarHost  = env.SONAR_HOST
    def projectKey = env.APP_NAME
    def sonarToken = ''

    withCredentials([string(credentialsId: 'sonarqube-token', variable: 'TOKEN')]) {
        sonarToken = TOKEN
    }

    def message = "### SonarQube Quality Gate\n\n**Status: FAILED**\n\n"

    try {
        def hotspotsRaw = sh(
            script: "curl -s -u '${sonarToken}:' '${sonarHost}/api/hotspots/search?projectKey=${projectKey}&status=TO_REVIEW'",
            returnStdout: true
        ).trim()
        def hotspotsJson = readJSON text: hotspotsRaw
        def hotspotList  = hotspotsJson.hotspots ?: []

        if (hotspotList.size() > 0) {
            message += "#### Security Hotspots — ${hotspotList.size()} unreviewed\n\n"
            hotspotList.take(10).each { h ->
                def file = h.component?.split(':')?.last() ?: 'unknown'
                message += "- **${h.vulnerabilityProbability ?: 'MEDIUM'}** | ${file} line ${h.line ?: '-'} | ${h.message ?: 'Security issue'}\n"
            }
            message += "\n"
        }

        def vulnsRaw = sh(
            script: "curl -s -u '${sonarToken}:' '${sonarHost}/api/issues/search?projectKeys=${projectKey}&types=VULNERABILITY&resolved=false'",
            returnStdout: true
        ).trim()
        def vulnsJson = readJSON text: vulnsRaw
        def vulnList  = vulnsJson.issues ?: []

        if (vulnList.size() > 0) {
            message += "#### Vulnerabilities — ${vulnList.size()} found\n\n"
            vulnList.take(10).each { v ->
                def file = v.component?.split(':')?.last() ?: 'unknown'
                message += "- **${v.severity ?: 'UNKNOWN'}** | ${file} line ${v.line ?: '-'} | ${v.message ?: 'Vulnerability'}\n"
            }
            message += "\n"
        }

        if (hotspotList.size() == 0 && vulnList.size() == 0) {
            message += "_Quality Gate failed. Check SonarQube directly._\n\n"
        }

    } catch (Exception e) {
        message += "_Could not fetch details: ${e.message}_\n\n"
    }

    message += "---\n[Review in SonarQube](${sonarHost}/dashboard?id=${projectKey})"
    return message
}

// ── Helper: post comment to GitLab commit ────────────────────────────────────
def postGitlabComment(String message) {
    def gitlabHost = env.GITLAB_HOST
    def projectId  = env.GITLAB_PROJECT_ID
    def commitSha  = env.APP_COMMIT ?: env.GIT_COMMIT

    if (!projectId || !commitSha) {
        echo "Skipping GitLab comment — project ID or commit SHA not available"
        return
    }

    withCredentials([string(credentialsId: 'gitlab-api-token', variable: 'GL_TOKEN')]) {
        writeFile file: 'comment-body.txt', text: message
        sh """
            python3 -c "
import json
with open('comment-body.txt', 'r') as f:
    note = f.read()
payload = json.dumps({'note': note})
with open('gitlab-comment.json', 'w') as f:
    f.write(payload)
"
            curl -s --request POST \\
              --header "PRIVATE-TOKEN: \$GL_TOKEN" \\
              --header "Content-Type: application/json" \\
              --data @gitlab-comment.json \\
              "${gitlabHost}/api/v4/projects/${projectId}/repository/commits/${commitSha}/comments"
            rm -f gitlab-comment.json comment-body.txt
        """
    }
}
