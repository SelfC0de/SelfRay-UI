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

**4. During install you'll be asked about SSL:**

```
  Your server IP: 103.80.86.204

  Do you have a domain pointed to this server?
  (A-record → 103.80.86.204)

  Enter domain (or press Enter to skip): vpn.example.com
```

**With domain** — Let's Encrypt certificate is issued automatically. Panel works over trusted HTTPS. VPN apps accept subscriptions without warnings.

**Without domain** — self-signed certificate is generated (10 years). Panel works over HTTPS but browsers will show a security warning. You can add a domain later in Settings → SSL.

**5. Save your credentials:**

```
  ✅ Installation complete!

  Panel URL    https://vpn.example.com:8443/login
  Login        admin
  Password     aBcDeFgHiJkL

  ⚠  Save your credentials! They won't show again.
```

---

## Features

| Feature | Status |
|---|---|
| VLESS + Reality + Vision | ✅ |
| VLESS + TLS | ✅ |
| VLESS + WebSocket | ✅ |
| VMess + WS / TCP / gRPC | ✅ |
| Trojan + TCP / gRPC + Reality | ✅ |
| Shadowsocks (2022) | ✅ |
| XHTTP (SplitHTTP) transport | ✅ |
| Transport: TCP, WS, gRPC, H2, HTTPUpgrade, XHTTP | ✅ |
| Security: None, TLS, Reality | ✅ |
| uTLS fingerprints (chrome, firefox, safari, etc.) | ✅ |
| Multi-client per inbound | ✅ |
| Auto-Generate 10 random inbounds | ✅ |
| Inbound presets (Speed, Stealth, Streaming, Gaming) | ✅ |
| Client traffic limit (MB / GB / TB) | ✅ |
| Client expiry (days) | ✅ |
| Client IP limit | ✅ |
| Traffic progress bar with remaining | ✅ |
| Online users indicator | ✅ |
| Subscription links (/sub/) | ✅ |
| Connection links (vless://, vmess://, ss://, trojan://) | ✅ |
| SSL: Let's Encrypt + self-signed | ✅ |
| 2FA (TOTP) authentication | ✅ |
| Telegram bot (status, change password/port) | ✅ |
| Telegram notifications (login, expiry, traffic) | ✅ |
| Cloudflare WARP+ outbound | ✅ |
| RU Whitelist routing (auto-update from GitHub) | ✅ |
| Fake website (20+ templates) | ✅ |
| Block BitTorrent | ✅ |
| Custom DNS / routing rules | ✅ |
| Database backup | ✅ |
| Reality key generation | ✅ |
| Docker support | ✅ |

---

## SSL Certificate

### Option A: Domain + Let's Encrypt (recommended)

1. Get a free domain (e.g. freedns.afraid.org, duckdns.org)
2. Create A-record pointing to your server IP
3. Enter domain during installation — certificate is issued automatically
4. Panel URL: `https://yourdomain.com:8443/login`

### Option B: Without domain (self-signed)

1. Press Enter when asked for domain during installation
2. Panel URL: `https://YOUR_IP:8443/login`
3. Browser will show "Connection not secure" — click "Advanced" → "Proceed"
4. You can add a domain later: Settings → SSL → enter domain → Issue Let's Encrypt

---

## Requirements

- Ubuntu 20.04+ / Debian 11+ / CentOS 8+
- Root access
- Open port 8443 (panel) + your inbound ports (e.g. 443)
- Port 80 free (for Let's Encrypt, only during certificate issuance)

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
https://YOUR_IP:8443/login
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
