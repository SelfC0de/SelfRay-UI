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
BG_D='\033[48;5;234m'
W='\033[0;37m'
BC='\033[1;36m'
BG='\033[1;32m'
BY='\033[1;33m'
BR='\033[1;31m'
BM='\033[1;35m'

REPO="SelfC0de/SelfRay-UI"
INSTALL_DIR="/opt/selfray-ui"
SERVICE_NAME="selfray-ui"
PANEL_PORT=8443

spin(){
    local pid=$1 msg=$2
    local sp='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
    local i=0
    while kill -0 "$pid" 2>/dev/null; do
        printf "\r  ${C}${sp:i++%${#sp}:1}${N} ${D}${msg}${N}  "
        sleep 0.1
    done
    wait "$pid" 2>/dev/null
    printf "\r                                                          \r"
}

ok()  { echo -e "  ${BG}✔${N}  $1"; }
inf() { echo -e "  ${BC}ℹ${N}  $1"; }
wrn() { echo -e "  ${BY}⚠${N}  $1"; }
err() { echo -e "  ${BR}✘${N}  $1"; }

step(){
    local num=$1 title=$2
    echo ""
    echo -e "  ${BG_D} ${BC}${num}${N}${BG_D} ${N} ${B}${title}${N}"
    echo -e "  ${D}$(printf '%.0s─' {1..46})${N}"
}

progress(){
    local pct=$1 w=40
    local filled=$((pct * w / 100))
    local empty=$((w - filled))
    printf "\r  ${D}[${N}"
    printf "${C}%0.s█${N}" $(seq 1 $filled 2>/dev/null) 2>/dev/null
    printf "${D}%0.s░${N}" $(seq 1 $empty 2>/dev/null) 2>/dev/null
    printf "${D}]${N} ${B}${pct}%%${N}  "
}

clear
echo ""
echo ""
sleep 0.1
echo -e "        ${C}╔══════════════════════════════════════╗${N}"
sleep 0.05
echo -e "        ${C}║${N}                                      ${C}║${N}"
sleep 0.05
echo -e "        ${C}║${N}    ${B}⚡ ${BC}S${C}elf${BC}R${C}ay${BC}-UI${N}                    ${C}║${N}"
sleep 0.05
echo -e "        ${C}║${N}                                      ${C}║${N}"
sleep 0.05
echo -e "        ${C}║${N}    ${D}Xray Management Panel${N}             ${C}║${N}"
sleep 0.05
echo -e "        ${C}║${N}    ${D}Fast · Lightweight · Secure${N}       ${C}║${N}"
sleep 0.05
echo -e "        ${C}║${N}                                      ${C}║${N}"
sleep 0.05
echo -e "        ${C}║${N}    ${D}github.com/SelfC0de/SelfRay-UI${N}   ${C}║${N}"
sleep 0.05
echo -e "        ${C}║${N}    ${D}t.me/selfcode_dev${N}                ${C}║${N}"
sleep 0.05
echo -e "        ${C}║${N}                                      ${C}║${N}"
sleep 0.05
echo -e "        ${C}╚══════════════════════════════════════╝${N}"
echo ""
sleep 0.3

if [ "$EUID" -ne 0 ]; then
    err "Root access required!"
    echo -e "  ${D}Run: sudo bash <(curl -Ls https://raw.githubusercontent.com/${REPO}/main/install.sh)${N}"
    exit 1
fi

# ══════════════════════════════════════
#  STEP 1: System Dependencies
# ══════════════════════════════════════
step "01" "System Dependencies"
(apt-get update -qq > /dev/null 2>&1 && apt-get install -y -qq python3 python3-pip python3-venv unzip wget curl git > /dev/null 2>&1) &
spin $! "Installing packages..."
ok "System packages ready"

# ══════════════════════════════════════
#  STEP 2: Download Panel
# ══════════════════════════════════════
step "02" "Downloading SelfRay-UI"
if [ -d "$INSTALL_DIR" ]; then
    wrn "Previous installation found"
    if [ -f "$INSTALL_DIR/data/selfray.db" ]; then
        cp "$INSTALL_DIR/data/selfray.db" /tmp/selfray_backup.db 2>/dev/null
        ok "Database backed up"
    fi
    rm -rf "$INSTALL_DIR"
fi

(git clone --depth 1 "https://github.com/${REPO}.git" "$INSTALL_DIR" > /dev/null 2>&1) &
spin $! "Cloning repository..."
ok "Repository cloned"

if [ -f /tmp/selfray_backup.db ]; then
    mkdir -p "$INSTALL_DIR/data"
    mv /tmp/selfray_backup.db "$INSTALL_DIR/data/selfray.db"
    ok "Database restored from backup"
fi

# ══════════════════════════════════════
#  STEP 3: Python Environment
# ══════════════════════════════════════
step "03" "Python Environment"
(python3 -m venv "$INSTALL_DIR/venv" && source "$INSTALL_DIR/venv/bin/activate" && pip install --quiet --no-cache-dir -r "$INSTALL_DIR/requirements.txt") &
spin $! "Setting up virtual environment..."
source "$INSTALL_DIR/venv/bin/activate"
ok "Python environment ready"
ok "Dependencies installed"

# ══════════════════════════════════════
#  STEP 4: Xray Core
# ══════════════════════════════════════
step "04" "Xray Core"
mkdir -p "$INSTALL_DIR/xray"
ARCH=$(uname -m)
case $ARCH in
    x86_64|amd64) XRAY_ARCH="64" ;;
    aarch64|arm64) XRAY_ARCH="arm64-v8a" ;;
    armv7l)        XRAY_ARCH="arm32-v7a" ;;
    armv6l)        XRAY_ARCH="arm32-v6" ;;
    *)             XRAY_ARCH="64" ;;
esac
(wget -q "https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-${XRAY_ARCH}.zip" -O /tmp/xray.zip && unzip -o /tmp/xray.zip -d "$INSTALL_DIR/xray" > /dev/null 2>&1 && chmod +x "$INSTALL_DIR/xray/xray" && rm -f /tmp/xray.zip) &
spin $! "Downloading latest Xray-core..."
XRAY_VER=$("$INSTALL_DIR/xray/xray" version 2>/dev/null | head -1 | awk '{print $2}' || echo "?")
ok "Xray-core ${BC}v${XRAY_VER}${N} installed"

# ══════════════════════════════════════
#  STEP 5: SSL Certificate
# ══════════════════════════════════════
step "05" "SSL Certificate"
CERT_DIR="$INSTALL_DIR/data/cert"
mkdir -p "$CERT_DIR"
SERVER_IP=$(curl -s4 --max-time 5 ifconfig.me 2>/dev/null || curl -s4 --max-time 5 api.ipify.org 2>/dev/null || echo "127.0.0.1")
SSL_DOMAIN=""

echo ""
echo -e "  ${B}Your server IP: ${BC}${SERVER_IP}${N}"
echo ""
echo -e "  ${D}A domain with Let's Encrypt gives you trusted HTTPS.${N}"
echo -e "  ${D}Without a domain, a self-signed certificate will be used.${N}"
echo ""
echo -e "  ${D}Point your domain A-record → ${W}${SERVER_IP}${N}"
echo ""
read -p "  $(echo -e "${BY}?${N}") Enter domain (or press Enter to skip): " SSL_DOMAIN
echo ""

if [ -n "$SSL_DOMAIN" ]; then
    inf "Issuing Let's Encrypt certificate for ${BC}${SSL_DOMAIN}${N}"
    apt-get install -y -qq certbot > /dev/null 2>&1
    certbot certonly --standalone --preferred-challenges http --http-01-port 80 \
        -d "$SSL_DOMAIN" --agree-tos --non-interactive --register-unsafely-without-email \
        --keep-until-expiring 2>/dev/null
    LE_CERT="/etc/letsencrypt/live/${SSL_DOMAIN}/fullchain.pem"
    LE_KEY="/etc/letsencrypt/live/${SSL_DOMAIN}/privkey.pem"
    if [ -f "$LE_CERT" ] && [ -f "$LE_KEY" ]; then
        cp "$LE_CERT" "$CERT_DIR/fullchain.pem"
        cp "$LE_KEY" "$CERT_DIR/privkey.pem"
        ok "Let's Encrypt certificate for ${BC}${SSL_DOMAIN}${N} ${BG}✔${N}"
    else
        wrn "Let's Encrypt failed — falling back to self-signed"
        SSL_DOMAIN=""
    fi
fi

if [ -z "$SSL_DOMAIN" ]; then
    if [ ! -f "$CERT_DIR/fullchain.pem" ]; then
        openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
            -keyout "$CERT_DIR/privkey.pem" -out "$CERT_DIR/fullchain.pem" \
            -days 3650 -nodes \
            -subj "/CN=SelfRay-UI" \
            -addext "subjectAltName=IP:${SERVER_IP},DNS:localhost,IP:127.0.0.1" 2>/dev/null
        ok "Self-signed certificate (10 years)"
    else
        ok "Existing certificate preserved"
    fi
fi

# ══════════════════════════════════════
#  STEP 6: Systemd Service
# ══════════════════════════════════════
step "06" "System Service"
cat > /etc/systemd/system/${SERVICE_NAME}.service << EOF
[Unit]
Description=SelfRay-UI Panel
After=network.target

[Service]
Type=simple
WorkingDirectory=${INSTALL_DIR}
ExecStart=${INSTALL_DIR}/venv/bin/python -m app.main
Restart=always
RestartSec=3
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable ${SERVICE_NAME} > /dev/null 2>&1
ok "Service created & enabled"

# ══════════════════════════════════════
#  STEP 7: Management Command
# ══════════════════════════════════════
step "07" "Management CLI"
cat > /usr/local/bin/selfray << 'MGMT'
#!/bin/bash
R='\033[0;31m';G='\033[0;32m';C='\033[0;36m';Y='\033[1;33m';M='\033[0;35m';B='\033[1m';D='\033[2m';N='\033[0m'
BC='\033[1;36m';BG='\033[1;32m';BY='\033[1;33m';BR='\033[1;31m'
SERVICE="selfray-ui"
DIR="/opt/selfray-ui"
ok()  { echo -e "  ${BG}✔${N}  $1"; }
inf() { echo -e "  ${BC}ℹ${N}  $1"; }
wrn() { echo -e "  ${BY}⚠${N}  $1"; }
err() { echo -e "  ${BR}✘${N}  $1"; }
case "$1" in
    start)   systemctl start $SERVICE && ok "Started" ;;
    stop)    systemctl stop $SERVICE && wrn "Stopped" ;;
    restart) systemctl restart $SERVICE && ok "Restarted" ;;
    status)  systemctl status $SERVICE --no-pager ;;
    log|logs) journalctl -u $SERVICE -f --no-hostname ;;
    creds)   journalctl -u $SERVICE --no-pager 2>/dev/null | grep -A4 "First Run" | tail -5 ;;
    reset-password)
        source "$DIR/venv/bin/activate"
        cd "$DIR"
        python3 -c "
import sys;sys.path.insert(0,'.')
from app.main import *
init_db()
import secrets
p=secrets.token_urlsafe(12)
c=get_db()
c.execute('DELETE FROM users')
c.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)',('admin',hash_password(p)))
c.commit();c.close()
print()
print('  Login:    admin')
print('  Password: '+p)
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
        echo -e "  ${BC}⚡ SelfRay-UI${N} ${D}— Management CLI${N}"
        echo ""
        echo -e "  ${B}Usage:${N} selfray <command>"
        echo ""
        echo -e "    ${BG}start${N}            Start panel"
        echo -e "    ${BR}stop${N}             Stop panel"
        echo -e "    ${BC}restart${N}          Restart panel"
        echo -e "    ${BC}status${N}           Show service status"
        echo -e "    ${BC}log${N}              View live logs"
        echo -e "    ${BY}creds${N}            Show saved credentials"
        echo -e "    ${BY}reset-password${N}   Generate new admin password"
        echo -e "    ${M}update${N}           Update from GitHub"
        echo -e "    ${BR}uninstall${N}        Remove completely"
        echo "" ;;
esac
MGMT
chmod +x /usr/local/bin/selfray
ok "CLI command ${BC}selfray${N} installed"

# ══════════════════════════════════════
#  LAUNCH
# ══════════════════════════════════════
step "⚡" "Launching SelfRay-UI"

progress 20
systemctl restart ${SERVICE_NAME}
progress 50
sleep 1
progress 70

if [ -z "$SERVER_IP" ]; then
    SERVER_IP=$(curl -s4 --max-time 5 ifconfig.me 2>/dev/null || curl -s4 --max-time 5 api.ipify.org 2>/dev/null || hostname -I | awk '{print $1}')
fi

if [ -n "$SSL_DOMAIN" ]; then
    source "$INSTALL_DIR/venv/bin/activate"
    python3 -c "
import sys;sys.path.insert(0,'$INSTALL_DIR')
from app.main import *
set_setting('ssl_domain', '$SSL_DOMAIN')
set_setting('ssl_enabled', 'true')
set_setting('ssl_cert_path', '$CERT_DIR/fullchain.pem')
set_setting('ssl_key_path', '$CERT_DIR/privkey.pem')
" 2>/dev/null
    systemctl restart ${SERVICE_NAME}
fi

progress 90
sleep 1

ADMIN_PASS=""
for i in 1 2 3; do
    ADMIN_PASS=$(journalctl -u $SERVICE_NAME --no-pager 2>/dev/null | grep "Admin Password" | tail -1 | awk '{print $NF}')
    [ -n "$ADMIN_PASS" ] && break; sleep 2
done

progress 100
echo ""
sleep 0.3

if [ -n "$SSL_DOMAIN" ]; then
    PANEL_URL="https://${SSL_DOMAIN}:${PANEL_PORT}/login"
    SSL_BADGE="${BG}Let's Encrypt ✔${N}"
else
    PANEL_URL="https://${SERVER_IP}:${PANEL_PORT}/login"
    SSL_BADGE="${BY}Self-Signed${N}"
fi

echo ""
echo ""
echo -e "  ${C}╔══════════════════════════════════════════════════════╗${N}"
echo -e "  ${C}║${N}                                                      ${C}║${N}"
echo -e "  ${C}║${N}   ${BG}✅  Installation Complete!${N}                         ${C}║${N}"
echo -e "  ${C}║${N}                                                      ${C}║${N}"
echo -e "  ${C}╠══════════════════════════════════════════════════════╣${N}"
echo -e "  ${C}║${N}                                                      ${C}║${N}"
echo -e "  ${C}║${N}   ${D}Panel URL${N}   ${BC}${PANEL_URL}${N}"
echo -e "  ${C}║${N}   ${D}Login${N}       ${BY}admin${N}"
echo -e "  ${C}║${N}   ${D}Password${N}    ${BY}${ADMIN_PASS:-selfray creds}${N}"
echo -e "  ${C}║${N}   ${D}SSL${N}         ${SSL_BADGE}"
echo -e "  ${C}║${N}   ${D}Xray${N}        ${BC}v${XRAY_VER}${N}"
echo -e "  ${C}║${N}                                                      ${C}║${N}"
echo -e "  ${C}╠══════════════════════════════════════════════════════╣${N}"
echo -e "  ${C}║${N}                                                      ${C}║${N}"
echo -e "  ${C}║${N}   ${BR}⚠  Save your credentials! They won't show again.${N}  ${C}║${N}"
echo -e "  ${C}║${N}                                                      ${C}║${N}"
echo -e "  ${C}╠══════════════════════════════════════════════════════╣${N}"
echo -e "  ${C}║${N}                                                      ${C}║${N}"
echo -e "  ${C}║${N}   ${D}Commands:${N}  selfray {start|stop|restart|log}       ${C}║${N}"
echo -e "  ${C}║${N}   ${D}Password:${N}  selfray reset-password                 ${C}║${N}"
echo -e "  ${C}║${N}   ${D}Update:${N}    selfray update                         ${C}║${N}"
echo -e "  ${C}║${N}   ${D}Telegram:${N}  ${BC}t.me/selfcode_dev${N}                     ${C}║${N}"
echo -e "  ${C}║${N}                                                      ${C}║${N}"
echo -e "  ${C}╚══════════════════════════════════════════════════════╝${N}"
echo ""
echo -e "  ${D}─── Copy-friendly credentials ───${N}"
echo ""
echo "  URL:       ${PANEL_URL}"
echo "  Login:     admin"
echo "  Password:  ${ADMIN_PASS:-selfray creds}"
echo ""
