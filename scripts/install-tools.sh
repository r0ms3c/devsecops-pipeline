#!/usr/bin/env bash
# =============================================================================
# DevSecOps Pipeline — Tool Installation Script
# Ubuntu 24.04 LTS
#
# Run as root or with sudo.
# Installs: Semgrep, Dependency-Check, SonarQube Scanner
# Does NOT install: Jenkins (see docs/installation.md), SonarQube server
# =============================================================================
set -euo pipefail

SEMGREP_VENV="/opt/semgrep-env"
DC_VERSION="12.1.0"
DC_HOME="/opt/dependency-check"
SONAR_VERSION="6.2.1.4610"
SONAR_HOME="/opt/sonar-scanner"

echo "=================================================="
echo " DevSecOps Pipeline — Tool Installation"
echo "=================================================="

# ── Semgrep ───────────────────────────────────────────────────────────────────
echo ""
echo "[1/3] Installing Semgrep..."
apt-get install -y python3-venv python3-pip --quiet
python3 -m venv "$SEMGREP_VENV"
"$SEMGREP_VENV/bin/pip" install semgrep --quiet
ln -sf "$SEMGREP_VENV/bin/semgrep" /usr/local/bin/semgrep
semgrep --version
echo "Semgrep installed at: $SEMGREP_VENV"

# ── Dependency-Check ──────────────────────────────────────────────────────────
echo ""
echo "[2/3] Installing Dependency-Check v${DC_VERSION}..."
apt-get install -y default-jdk --quiet
DC_ZIP="dependency-check-${DC_VERSION}-release.zip"
DC_URL="https://github.com/jeremylong/DependencyCheck/releases/download/v${DC_VERSION}/${DC_ZIP}"
wget -q "$DC_URL" -O "/tmp/${DC_ZIP}"
unzip -q "/tmp/${DC_ZIP}" -d /opt
mv /opt/dependency-check "$DC_HOME" 2>/dev/null || true
chmod +x "$DC_HOME/bin/dependency-check.sh"
rm "/tmp/${DC_ZIP}"
echo "Dependency-Check installed at: $DC_HOME"
echo ""
echo "  IMPORTANT: Populate the NVD database before first scan:"
echo "  Get a free API key at: https://nvd.nist.gov/developers/request-an-api-key"
echo "  Then run the Jenkins job: dependency-check-db-update"
echo "  Or manually: $DC_HOME/bin/dependency-check.sh --updateonly --nvdApiKey YOUR_KEY"

# ── SonarQube Scanner ─────────────────────────────────────────────────────────
echo ""
echo "[3/3] Installing SonarQube Scanner v${SONAR_VERSION}..."
SONAR_ZIP="sonar-scanner-cli-${SONAR_VERSION}-linux-x64.zip"
SONAR_URL="https://binaries.sonarsource.com/Distribution/sonar-scanner-cli/${SONAR_ZIP}"
wget -q "$SONAR_URL" -O "/tmp/${SONAR_ZIP}"
unzip -q "/tmp/${SONAR_ZIP}" -d "$SONAR_HOME"
chmod +x "$SONAR_HOME/sonar-scanner-${SONAR_VERSION}-linux-x64/bin/sonar-scanner"
ln -sf "$SONAR_HOME/sonar-scanner-${SONAR_VERSION}-linux-x64/bin/sonar-scanner" \
       /usr/local/bin/sonar-scanner
rm "/tmp/${SONAR_ZIP}"

# Configure SonarQube server address
echo ""
read -rp "Enter your SonarQube server URL (e.g. http://192.168.1.10:9000): " SONAR_HOST
SONAR_PROPS="$SONAR_HOME/sonar-scanner-${SONAR_VERSION}-linux-x64/conf/sonar-scanner.properties"
echo "sonar.host.url=${SONAR_HOST}" >> "$SONAR_PROPS"
echo "SonarQube Scanner installed at: $SONAR_HOME"

echo ""
echo "=================================================="
echo " Installation complete"
echo "=================================================="
echo ""
echo "Tools installed:"
echo "  semgrep    -> $(which semgrep)"
echo "  dep-check  -> $DC_HOME/bin/dependency-check.sh"
echo "  sonar-scan -> $(which sonar-scanner)"
echo ""
echo "Next steps:"
echo "  1. Update Jenkinsfile environment variables with your server IPs"
echo "  2. Create Jenkins credentials (see docs/jenkins-setup.md)"
echo "  3. Populate NVD database (see above)"
echo "  4. Create first Jenkins pipeline job (see docs/onboarding.md)"
