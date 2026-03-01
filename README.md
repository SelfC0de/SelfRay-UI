# <img src="app/static/logo.png" width="40" align="center"> SelfRay-UI

Lightweight Xray management panel. One command install. Full protocol support.

Python + FastAPI backend, zero npm/webpack/Go compilation.

---

## Quick Install

**1. Connect to your VPS via SSH**

```bash
ssh root@YOUR_SERVER_IP
```

**2. Update system packages**

```bash
apt update && apt upgrade -y
```

**3. Install SelfRay-UI**

```bash
bash <(curl -Ls https://raw.githubusercontent.com/SelfC0de/SelfRay-UI/main/install.sh)
```

**4. After install you'll see credentials — save them:**

```
  Panel:  http://YOUR_IP:8443

  ┌──────────────────────────────────────────┐
  │   Login:     admin                       │
  │   Password:  aBcDeFgHiJkL               │
  └──────────────────────────────────────────┘

  ⚠  SAVE THESE CREDENTIALS!
```

**5. Open panel in browser**

```
http://YOUR_IP:8443
```

---

## Features

| Feature | Status |
|---|---|
| VLESS + Reality + Vision | ✅ |
| VLESS + TLS | ✅ |
| VLESS + WebSocket | ✅ |
| VMess + WS / TCP / gRPC | ✅ |
| Trojan + TLS / Reality | ✅ |
| Shadowsocks (2022) | ✅ |
| Transport: TCP (RAW), WS, gRPC, H2, HTTPUpgrade | ✅ |
| Security: None, TLS, Reality | ✅ |
| uTLS: chrome, firefox, safari, ios, android, edge, 360, qq, random, randomized, unsafe | ✅ |
| Multi-client per inbound | ✅ |
| Client traffic limit (GB) | ✅ |
| Client expiry (days) | ✅ |
| Client IP limit | ✅ |
| Subscription links (/sub/) | ✅ |
| Connection links (vless://, vmess://, etc) | ✅ |
| Block BitTorrent | ✅ |
| Custom DNS | ✅ |
| Custom routing rules | ✅ |
| Xray auto-install from GitHub | ✅ |
| Database backup/export | ✅ |
| Reality key generation (in panel) | ✅ |
| Sniffing configuration | ✅ |
| systemd service | ✅ |
| Docker support | ✅ |

---

## Requirements

- Ubuntu 20.04+ / Debian 11+ / CentOS 8+
- Root access
- Open port 8443 (panel) + your inbound ports (e.g. 443)

---

## Management Commands

```bash
selfray start          # Start panel
selfray stop           # Stop panel
selfray restart        # Restart panel
selfray status         # Show status
selfray log            # View live logs
selfray creds          # Show login credentials
selfray reset-password # Generate new admin password
selfray update         # Update from GitHub
selfray uninstall      # Remove completely
```

---

## Docker Install

**1. Clone repository**

```bash
git clone https://github.com/SelfC0de/SelfRay-UI.git
```

**2. Start container**

```bash
cd SelfRay-UI
docker compose up -d
```

**3. Check credentials**

```bash
docker logs selfray-ui 2>&1 | grep Password
```

**4. Open panel**

```
http://YOUR_IP:8443
```

---

## Manual Install

**1. Clone repository**

```bash
git clone https://github.com/SelfC0de/SelfRay-UI.git /opt/selfray-ui
cd /opt/selfray-ui
```

**2. Create Python environment**

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

**3. Install xray-core**

```bash
mkdir -p xray
wget https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip -O /tmp/xray.zip
unzip /tmp/xray.zip -d xray/
chmod +x xray/xray
```

**4. Run**

```bash
python -m uvicorn app.main:app --host 0.0.0.0 --port 8443
```

---

## Uninstall

```bash
selfray uninstall
```

Removes: panel, xray-core, database, systemd service, `selfray` command.

---

## Contacts

- Telegram: [@selfcode_dev](https://t.me/selfcode_dev)
- GitHub: [SelfC0de](https://github.com/SelfC0de)

---

MIT License
