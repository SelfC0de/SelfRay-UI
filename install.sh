#!/bin/bash
set -e

R='\033[0;31m'
G='\033[0;32m'
C='\033[0;36m'
Y='\033[1;33m'
M='\033[0;35m'
B='\033[1m'
D='\033[2m'
N='\033[0m'

REPO="SelfC0de/SelfRay-UI"
INSTALL_DIR="/opt/selfray-ui"
SERVICE_NAME="selfray-ui"
PANEL_PORT=8443

ok()  { echo -e "  ${G}●${N} $1"; }
inf() { echo -e "  ${C}◆${N} $1"; }
wrn() { echo -e "  ${Y}▲${N} $1"; }
err() { echo -e "  ${R}✕${N} $1"; }
step(){ echo -e "\n${M}━━━${N} ${B}$1${N} ${M}━━━${N}"; }

clear
echo ""
echo -e "${C}  ┌─────────────────────────────────────────────┐${N}"
echo -e "${C}  │                                             │${N}"
echo -e "${C}  │   ${B}⚡ SelfRay-UI${N}${C}                             │${N}"
echo -e "${C}  │   ${D}Xray Panel Manager${N}${C}                        │${N}"
echo -e "${C}  │   ${D}t.me/selfcode_dev${N}${C}                         │${N}"
echo -e "${C}  │                                             │${N}"
echo -e "${C}  └─────────────────────────────────────────────┘${N}"
echo ""

if [ "$EUID" -ne 0 ]; then
    err "Run as root!"
    echo -e "  ${D}sudo bash <(curl -Ls https://raw.githubusercontent.com/${REPO}/main/install.sh)${N}"
    exit 1
fi

# ── Step 1 ──
step "Installing system dependencies"
apt-get update -qq > /dev/null 2>&1
apt-get install -y -qq python3 python3-pip python3-venv unzip wget curl git > /dev/null 2>&1
ok "python3, pip, venv, unzip, wget, curl, git"

# ── Step 2 ──
step "Downloading SelfRay-UI"
if [ -d "$INSTALL_DIR" ]; then
    wrn "Existing installation found"
    if [ -f "$INSTALL_DIR/data/selfray.db" ]; then
        cp "$INSTALL_DIR/data/selfray.db" /tmp/selfray_backup.db 2>/dev/null
        ok "Database backed up"
    fi
    rm -rf "$INSTALL_DIR"
fi

git clone --depth 1 "https://github.com/${REPO}.git" "$INSTALL_DIR" > /dev/null 2>&1
ok "Cloned from GitHub"

if [ -f /tmp/selfray_backup.db ]; then
    mkdir -p "$INSTALL_DIR/data"
    mv /tmp/selfray_backup.db "$INSTALL_DIR/data/selfray.db"
    ok "Database restored"
fi

# ── Step 3 ──
step "Setting up Python environment"
python3 -m venv "$INSTALL_DIR/venv"
source "$INSTALL_DIR/venv/bin/activate"
pip install --quiet --no-cache-dir -r "$INSTALL_DIR/requirements.txt"
ok "Virtual environment ready"
ok "Dependencies installed"

# ── Step 4 ──
step "Downloading Xray-core"
mkdir -p "$INSTALL_DIR/xray"
ARCH=$(uname -m)
case $ARCH in
    x86_64|amd64) XRAY_ARCH="64" ;;
    aarch64|arm64) XRAY_ARCH="arm64-v8a" ;;
    armv7l)        XRAY_ARCH="arm32-v7a" ;;
    armv6l)        XRAY_ARCH="arm32-v6" ;;
    *)             XRAY_ARCH="64" ;;
esac
wget -q "https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-${XRAY_ARCH}.zip" -O /tmp/xray.zip
unzip -o /tmp/xray.zip -d "$INSTALL_DIR/xray" > /dev/null 2>&1
chmod +x "$INSTALL_DIR/xray/xray"
rm -f /tmp/xray.zip
XRAY_VER=$("$INSTALL_DIR/xray/xray" version 2>/dev/null | head -1 || echo "unknown")
ok "Xray-core: ${C}${XRAY_VER}${N}"

# ── Step 5 ──
step "Creating systemd service"
cat > /etc/systemd/system/${SERVICE_NAME}.service << EOF
[Unit]
Description=SelfRay-UI Panel
After=network.target

[Service]
Type=simple
WorkingDirectory=${INSTALL_DIR}
ExecStart=${INSTALL_DIR}/venv/bin/python -m uvicorn app.main:app --host 0.0.0.0 --port ${PANEL_PORT}
Restart=always
RestartSec=3
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable ${SERVICE_NAME} > /dev/null 2>&1
ok "Service created & enabled"

# ── Step 6 ──
step "Creating management command"
cat > /usr/local/bin/selfray << 'MGMT'
#!/bin/bash
R='\033[0;31m';G='\033[0;32m';C='\033[0;36m';Y='\033[1;33m';M='\033[0;35m';B='\033[1m';D='\033[2m';N='\033[0m'
SERVICE="selfray-ui"
DIR="/opt/selfray-ui"
ok()  { echo -e "  ${G}●${N} $1"; }
inf() { echo -e "  ${C}◆${N} $1"; }
wrn() { echo -e "  ${Y}▲${N} $1"; }
err() { echo -e "  ${R}✕${N} $1"; }
case "$1" in
    start)   systemctl start $SERVICE && ok "Started" ;;
    stop)    systemctl stop $SERVICE && wrn "Stopped" ;;
    restart) systemctl restart $SERVICE && ok "Restarted" ;;
    status)  systemctl status $SERVICE --no-pager ;;
    log|logs) journalctl -u $SERVICE -f --no-hostname ;;
    creds)   journalctl -u $SERVICE --no-pager 2>/dev/null | grep -A4 "First Run" | tail -5 ;;
    reset-password)
        source "$DIR/venv/bin/activate"
        python3 -c "
import sys;sys.path.insert(0,'$DIR')
from app.main import *
init_db()
import secrets
p=secrets.token_urlsafe(12)
c=get_db()
c.execute('UPDATE users SET password_hash=? WHERE username=\"admin\"',(hash_password(p),))
c.commit();c.close()
print()
print('  New password: '+p)
print()
"
        systemctl restart $SERVICE
        ok "Password changed & service restarted" ;;
    update)
        inf "Updating SelfRay-UI..."
        cd "$DIR" && git pull origin main
        source "$DIR/venv/bin/activate"
        pip install --quiet -r requirements.txt
        systemctl restart $SERVICE
        ok "Updated & restarted" ;;
    uninstall)
        read -p "  Remove SelfRay-UI completely? [y/N] " c
        if [[ "$c" =~ ^[Yy]$ ]]; then
            wrn "Stopping services..."
            systemctl stop $SERVICE 2>/dev/null
            systemctl disable $SERVICE 2>/dev/null
            pkill -f "xray run" 2>/dev/null
            pkill -f "uvicorn app.main" 2>/dev/null
            wrn "Removing files..."
            rm -f /etc/systemd/system/${SERVICE}.service
            rm -f /usr/local/bin/selfray
            rm -rf "$DIR"
            systemctl daemon-reload
            ok "SelfRay-UI fully removed"
        fi ;;
    *)
        echo ""
        echo -e "  ${C}${B}⚡ SelfRay-UI${N}"
        echo ""
        echo -e "  ${B}Usage:${N} selfray <command>"
        echo ""
        echo -e "  ${G}start${N}           Start panel"
        echo -e "  ${R}stop${N}            Stop panel"
        echo -e "  ${C}restart${N}         Restart panel"
        echo -e "  ${C}status${N}          Show service status"
        echo -e "  ${C}log${N}             View live logs"
        echo -e "  ${Y}creds${N}           Show saved credentials"
        echo -e "  ${Y}reset-password${N}  Generate new admin password"
        echo -e "  ${M}update${N}          Update from GitHub"
        echo -e "  ${R}uninstall${N}       Remove completely"
        echo "" ;;
esac
MGMT
chmod +x /usr/local/bin/selfray
ok "Command 'selfray' installed"

# ── Start ──
step "Starting SelfRay-UI"
systemctl restart ${SERVICE_NAME}
sleep 3

SERVER_IP=$(curl -s4 --max-time 5 ifconfig.me 2>/dev/null || curl -s4 --max-time 5 api.ipify.org 2>/dev/null || hostname -I | awk '{print $1}')
ADMIN_PASS=""
for i in 1 2 3; do
    ADMIN_PASS=$(journalctl -u $SERVICE_NAME --no-pager 2>/dev/null | grep "Admin Password" | tail -1 | awk '{print $NF}')
    [ -n "$ADMIN_PASS" ] && break; sleep 2
done

PANEL_URL="http://${SERVER_IP}:${PANEL_PORT}"

echo ""
echo -e "${G}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${N}"
echo ""
echo -e "  ${G}${B}✅ Installation complete!${N}"
echo ""
echo -e "${C}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${N}"
echo ""
echo -e "  ${D}Panel URL${N}"
echo -e "  ${B}${C}${PANEL_URL}${N}"
echo ""
echo -e "  ${D}Login${N}"
echo -e "  ${B}${Y}admin${N}"
echo ""
echo -e "  ${D}Password${N}"
echo -e "  ${B}${Y}${ADMIN_PASS:-check: selfray creds}${N}"
echo ""
echo -e "${C}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${N}"
echo ""
echo -e "  ${R}⚠  Save your credentials! They won't show again.${N}"
echo ""
echo -e "  ${D}Management:${N}  selfray {start|stop|restart|status|log}"
echo -e "  ${D}Credentials:${N} selfray creds"
echo -e "  ${D}Update:${N}      selfray update"
echo -e "  ${D}Telegram:${N}    ${C}t.me/selfcode_dev${N}"
echo ""
echo -e "${G}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${N}"
echo ""
