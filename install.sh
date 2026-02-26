#!/bin/bash
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

REPO="SelfC0de/SelfRay-UI"
INSTALL_DIR="/opt/selfray-ui"
SERVICE_NAME="selfray-ui"
PANEL_PORT=8443

clear
echo -e "${CYAN}"
echo "  ╔═══════════════════════════════════════════╗"
echo "  ║          ⚡ SelfRay-UI Installer           ║"
echo "  ║            Xray Panel Manager              ║"
echo "  ║        t.me/selfcode_dev                   ║"
echo "  ╚═══════════════════════════════════════════╝"
echo -e "${NC}"

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Error: Run as root!${NC}"
    echo -e "Usage: ${CYAN}sudo bash <(curl -Ls https://raw.githubusercontent.com/${REPO}/main/install.sh)${NC}"
    exit 1
fi

echo -e "${GREEN}[1/6]${NC} Installing system dependencies..."
apt-get update -qq > /dev/null 2>&1
apt-get install -y -qq python3 python3-pip python3-venv unzip wget curl git > /dev/null 2>&1
echo -e "  ${GREEN}✓${NC} Done"

echo -e "${GREEN}[2/6]${NC} Downloading SelfRay-UI..."
if [ -d "$INSTALL_DIR" ]; then
    echo -e "  ${YELLOW}Existing installation found, backing up data...${NC}"
    [ -f "$INSTALL_DIR/data/selfray.db" ] && cp "$INSTALL_DIR/data/selfray.db" /tmp/selfray_backup.db 2>/dev/null
    rm -rf "$INSTALL_DIR"
fi

git clone --depth 1 "https://github.com/${REPO}.git" "$INSTALL_DIR" > /dev/null 2>&1
echo -e "  ${GREEN}✓${NC} Done"

if [ -f /tmp/selfray_backup.db ]; then
    mkdir -p "$INSTALL_DIR/data"
    mv /tmp/selfray_backup.db "$INSTALL_DIR/data/selfray.db"
    echo -e "  ${GREEN}✓${NC} Database restored"
fi

echo -e "${GREEN}[3/6]${NC} Setting up Python environment..."
python3 -m venv "$INSTALL_DIR/venv"
source "$INSTALL_DIR/venv/bin/activate"
pip install --quiet --no-cache-dir -r "$INSTALL_DIR/requirements.txt"
echo -e "  ${GREEN}✓${NC} Done"

echo -e "${GREEN}[4/6]${NC} Downloading Xray-core (latest)..."
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
echo -e "  ${GREEN}✓${NC} ${CYAN}${XRAY_VER}${NC}"

echo -e "${GREEN}[5/6]${NC} Creating systemd service..."
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
echo -e "  ${GREEN}✓${NC} Done"

echo -e "${GREEN}[6/6]${NC} Creating management command..."
cat > /usr/local/bin/selfray << 'MGMT'
#!/bin/bash
RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; NC='\033[0m'
SERVICE="selfray-ui"
DIR="/opt/selfray-ui"
case "$1" in
    start)   systemctl start $SERVICE && echo -e "${GREEN}✓ Started${NC}" ;;
    stop)    systemctl stop $SERVICE && echo -e "${RED}■ Stopped${NC}" ;;
    restart) systemctl restart $SERVICE && echo -e "${GREEN}✓ Restarted${NC}" ;;
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
print('New password: '+p)
"
        systemctl restart $SERVICE ;;
    update)
        echo -e "${CYAN}Updating...${NC}"
        cd "$DIR" && git pull origin main
        source "$DIR/venv/bin/activate"
        pip install --quiet -r requirements.txt
        systemctl restart $SERVICE
        echo -e "${GREEN}✓ Updated${NC}" ;;
    uninstall)
        read -p "Remove SelfRay-UI completely? [y/N] " c
        if [[ "$c" =~ ^[Yy]$ ]]; then
            echo -e "${YELLOW}Stopping services...${NC}"
            systemctl stop $SERVICE 2>/dev/null
            systemctl disable $SERVICE 2>/dev/null
            pkill -f "xray run" 2>/dev/null
            pkill -f "uvicorn app.main" 2>/dev/null
            echo -e "${YELLOW}Removing files...${NC}"
            rm -f /etc/systemd/system/${SERVICE}.service
            rm -f /usr/local/bin/selfray
            rm -rf "$DIR"
            systemctl daemon-reload
            echo -e "${GREEN}✓ SelfRay-UI fully removed${NC}"
        fi ;;
    *)
        echo -e "${CYAN}⚡ SelfRay-UI${NC}"
        echo "  selfray start|stop|restart|status|log"
        echo "  selfray creds|reset-password|update|uninstall" ;;
esac
MGMT
chmod +x /usr/local/bin/selfray
echo -e "  ${GREEN}✓${NC} Done"

echo -e "\n${GREEN}Starting SelfRay-UI...${NC}"
systemctl restart ${SERVICE_NAME}
sleep 3

SERVER_IP=$(curl -s4 --max-time 5 ifconfig.me 2>/dev/null || curl -s4 --max-time 5 api.ipify.org 2>/dev/null || hostname -I | awk '{print $1}')
ADMIN_PASS=""
for i in 1 2 3; do
    ADMIN_PASS=$(journalctl -u $SERVICE_NAME --no-pager 2>/dev/null | grep "Admin Password" | tail -1 | awk '{print $NF}')
    [ -n "$ADMIN_PASS" ] && break; sleep 2
done

echo ""
echo -e "${CYAN}════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  ${GREEN}${BOLD}✅ SelfRay-UI installed!${NC}"
echo ""
echo -e "  Panel:  ${CYAN}http://${SERVER_IP}:${PANEL_PORT}${NC}"
echo ""
echo -e "  ┌──────────────────────────────────────────────┐"
echo -e "  │                                              │"
echo -e "  │   Login:     ${YELLOW}admin${NC}                           │"
echo -e "  │   Password:  ${YELLOW}${ADMIN_PASS:-run: selfray creds}${NC}  │"
echo -e "  │                                              │"
echo -e "  └──────────────────────────────────────────────┘"
echo ""
echo -e "  ${RED}⚠  SAVE THESE CREDENTIALS!${NC}"
echo ""
echo -e "  ${CYAN}selfray${NC} {start|stop|restart|status|log|creds|update}"
echo ""
echo -e "${CYAN}════════════════════════════════════════════════════════${NC}"
echo ""
