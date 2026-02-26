# ⚡ SelfRay-UI

Lightweight Xray panel. One command install. Full protocol support.

**Simpler alternative to 3X-UI** — Python + FastAPI backend, zero npm/webpack/Go compilation.

---

## Quick Install

```bash
bash <(curl -Ls https://raw.githubusercontent.com/SelfC0de/SelfRay-UI/main/install.sh)
```

That's it. After install you'll see:

```
  Panel:  http://YOUR_IP:8443

  ┌──────────────────────────────────────────┐
  │   Login:     admin                       │
  │   Password:  aBcDeFgHiJkL               │
  └──────────────────────────────────────────┘

  ⚠  SAVE THESE CREDENTIALS!
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
| Transport: TCP, WS, gRPC, H2, HTTPUpgrade | ✅ |
| Security: None, TLS, Reality | ✅ |
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
| Reality key generation | ✅ |
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

```bash
git clone https://github.com/SelfC0de/SelfRay-UI.git
cd SelfRay-UI
docker compose up -d
```

Panel: `http://YOUR_IP:8443`

Check credentials:
```bash
docker logs selfray-ui 2>&1 | grep Password
```

---

## Manual Install

```bash
# 1. Clone
git clone https://github.com/SelfC0de/SelfRay-UI.git /opt/selfray-ui
cd /opt/selfray-ui

# 2. Python venv
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# 3. Install xray-core
mkdir -p xray
wget https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip -O /tmp/xray.zip
unzip /tmp/xray.zip -d xray/
chmod +x xray/xray

# 4. Run
python -m uvicorn app.main:app --host 0.0.0.0 --port 8443
```

---

## Typical Setup: VLESS + Reality

1. Install panel on your VPS
2. Open panel → Inbounds → **+ New Inbound**
3. Settings:
   - Protocol: **VLESS**
   - Port: **443**
   - Network: **TCP**
   - Security: **Reality**
   - Flow: **xtls-rprx-vision**
   - Dest: **google.com:443**
   - Server Names: **google.com**
   - Click **🔑 Generate Keys**
4. Click **Create Inbound**
5. Click **Link** on the client → copy link → paste into v2rayN / Hiddify / NekoBox

---

## Project Structure

```
SelfRay-UI/
├── app/
│   ├── main.py          # Backend (FastAPI)
│   └── templates/
│       ├── login.html   # Login page
│       └── panel.html   # Main panel
├── data/                # SQLite DB + xray config (created at runtime)
├── xray/                # Xray-core binary (downloaded at install)
├── install.sh           # One-command installer
├── requirements.txt     # Python deps
├── Dockerfile
├── docker-compose.yml
└── LICENSE
```

---

## Contacts

- Telegram: [@selfcode_dev](https://t.me/selfcode_dev)
- GitHub: [SelfC0de](https://github.com/SelfC0de)

---

MIT License
