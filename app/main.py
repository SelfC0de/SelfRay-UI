import os
import sys
import json
import uuid
import shutil
import signal
import sqlite3
import hashlib
import secrets
import logging
import subprocess
import platform
import asyncio
import base64
import urllib.parse
from pathlib import Path
from datetime import datetime, timedelta
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response, Depends, HTTPException, Form
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
from pydantic import BaseModel
from typing import Optional, List

BASE_DIR = Path(__file__).parent.parent
APP_DIR = Path(__file__).parent
DATA_DIR = BASE_DIR / "data"
XRAY_DIR = BASE_DIR / "xray"
DB_PATH = DATA_DIR / "selfray.db"
XRAY_CONFIG_PATH = DATA_DIR / "xray_config.json"
XRAY_BIN = XRAY_DIR / "xray"

LOG_FORMAT = "%(asctime)s [%(levelname)s] %(message)s"
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)
logger = logging.getLogger("selfray")

xray_process: Optional[subprocess.Popen] = None

# ═══════════════════════════════════════════
#  DATABASE
# ═══════════════════════════════════════════

def get_db():
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS inbounds (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tag TEXT UNIQUE NOT NULL,
            protocol TEXT NOT NULL,
            listen TEXT DEFAULT '',
            port INTEGER NOT NULL,
            settings TEXT NOT NULL DEFAULT '{}',
            stream_settings TEXT NOT NULL DEFAULT '{}',
            sniffing TEXT NOT NULL DEFAULT '{}',
            allocate TEXT NOT NULL DEFAULT '{}',
            enabled INTEGER DEFAULT 1,
            remark TEXT DEFAULT '',
            created_at TEXT DEFAULT (datetime('now')),
            updated_at TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS clients (
            id TEXT PRIMARY KEY,
            inbound_id INTEGER NOT NULL,
            email TEXT NOT NULL,
            uuid TEXT NOT NULL,
            flow TEXT DEFAULT '',
            enabled INTEGER DEFAULT 1,
            expiry_time INTEGER DEFAULT 0,
            traffic_limit INTEGER DEFAULT 0,
            upload INTEGER DEFAULT 0,
            download INTEGER DEFAULT 0,
            ip_limit INTEGER DEFAULT 0,
            created_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (inbound_id) REFERENCES inbounds(id) ON DELETE CASCADE
        );
    """)
    conn.commit()
    conn.close()


def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


def get_setting(key: str, default: str = "") -> str:
    conn = get_db()
    row = conn.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    conn.close()
    return row["value"] if row else default


def set_setting(key: str, value: str):
    conn = get_db()
    conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, value))
    conn.commit()
    conn.close()


def setup_admin():
    conn = get_db()
    admin = conn.execute("SELECT * FROM users LIMIT 1").fetchone()
    if not admin:
        username = "admin"
        password = secrets.token_urlsafe(12)
        conn.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username, hash_password(password))
        )
        conn.commit()
        logger.info("=" * 50)
        logger.info("  SelfRay-UI First Run")
        logger.info(f"  Admin Login: {username}")
        logger.info(f"  Admin Password: {password}")
        logger.info("  SAVE THIS! It won't be shown again.")
        logger.info("=" * 50)
    conn.close()
    cert_file = DATA_DIR / "cert" / "fullchain.pem"
    key_file = DATA_DIR / "cert" / "privkey.pem"
    if cert_file.exists() and key_file.exists() and not get_setting("ssl_cert_path", ""):
        set_setting("ssl_cert_path", str(cert_file))
        set_setting("ssl_key_path", str(key_file))
        set_setting("ssl_enabled", "true")
        logger.info("SSL auto-configured from existing certificate")


# ═══════════════════════════════════════════
#  XRAY CONFIG GENERATION
# ═══════════════════════════════════════════

def generate_xray_config():
    conn = get_db()
    inbounds_rows = conn.execute("SELECT * FROM inbounds WHERE enabled=1").fetchall()

    xray_inbounds = []
    for ib in inbounds_rows:
        clients_rows = conn.execute(
            "SELECT * FROM clients WHERE inbound_id=? AND enabled=1", (ib["id"],)
        ).fetchall()

        settings = json.loads(ib["settings"])
        stream = json.loads(ib["stream_settings"])
        sniffing = json.loads(ib["sniffing"]) if ib["sniffing"] else {"enabled": True, "destOverride": ["http", "tls", "quic"]}

        if ib["protocol"] in ("vless", "vmess", "trojan"):
            client_list = []
            for c in clients_rows:
                if ib["protocol"] == "vless":
                    obj = {"id": c["uuid"], "email": c["email"], "flow": c["flow"] or ""}
                elif ib["protocol"] == "vmess":
                    obj = {"id": c["uuid"], "email": c["email"], "alterId": 0}
                elif ib["protocol"] == "trojan":
                    obj = {"password": c["uuid"], "email": c["email"]}
                client_list.append(obj)
            settings["clients"] = client_list

        inbound_config = {
            "tag": ib["tag"],
            "listen": ib["listen"] or "",
            "port": ib["port"],
            "protocol": ib["protocol"],
            "settings": settings,
            "streamSettings": stream,
            "sniffing": sniffing
        }

        allocate = json.loads(ib["allocate"]) if ib["allocate"] and ib["allocate"] != '{}' else None
        if allocate and allocate.get("strategy"):
            inbound_config["allocate"] = allocate

        xray_inbounds.append(inbound_config)

    api_port = int(get_setting("xray_api_port", "10085"))

    log_level = get_setting("xray_log_level", "warning")

    routing_rules = [
        {"type": "field", "inboundTag": ["api-in"], "outboundTag": "api"}
    ]

    block_bt = get_setting("block_bittorrent", "true") == "true"
    if block_bt:
        routing_rules.append({"type": "field", "protocol": ["bittorrent"], "outboundTag": "blocked"})

    custom_routing = get_setting("custom_routing_rules", "")
    if custom_routing:
        try:
            extra = json.loads(custom_routing)
            if isinstance(extra, list):
                routing_rules.extend(extra)
        except:
            pass

    dns_config = {}
    custom_dns = get_setting("custom_dns", "")
    if custom_dns:
        try:
            dns_config = json.loads(custom_dns)
        except:
            dns_config = {"servers": ["1.1.1.1", "8.8.8.8"]}

    config = {
        "log": {"loglevel": log_level},
        "api": {"tag": "api", "services": ["StatsService", "HandlerService"]},
        "stats": {},
        "policy": {
            "levels": {"0": {"statsUserUplink": True, "statsUserDownlink": True}},
            "system": {"statsInboundUplink": True, "statsInboundDownlink": True, "statsOutboundUplink": True, "statsOutboundDownlink": True}
        },
        "inbounds": [
            {
                "tag": "api-in",
                "listen": "127.0.0.1",
                "port": api_port,
                "protocol": "dokodemo-door",
                "settings": {"address": "127.0.0.1"}
            },
            *xray_inbounds
        ],
        "outbounds": [
            {"tag": "direct", "protocol": "freedom"},
            {"tag": "blocked", "protocol": "blackhole"}
        ],
        "routing": {"rules": routing_rules}
    }

    custom_outbounds = get_setting("custom_outbounds", "")
    if custom_outbounds:
        try:
            extra_ob = json.loads(custom_outbounds)
            existing_tags = {o["tag"] for o in config["outbounds"]}
            for ob in extra_ob:
                if ob.get("tag") not in existing_tags:
                    config["outbounds"].append(ob)
        except:
            pass

    if dns_config:
        config["dns"] = dns_config

    conn.close()
    with open(XRAY_CONFIG_PATH, "w") as f:
        json.dump(config, f, indent=2)
    return config


# ═══════════════════════════════════════════
#  XRAY PROCESS
# ═══════════════════════════════════════════

def start_xray():
    global xray_process
    stop_xray()
    if not XRAY_BIN.exists():
        logger.error(f"Xray binary not found: {XRAY_BIN}")
        return False
    generate_xray_config()
    try:
        xray_process = subprocess.Popen(
            [str(XRAY_BIN), "run", "-c", str(XRAY_CONFIG_PATH)],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT
        )
        logger.info(f"Xray started (PID: {xray_process.pid})")
        return True
    except Exception as e:
        logger.error(f"Failed to start xray: {e}")
        return False


def stop_xray():
    global xray_process
    if xray_process and xray_process.poll() is None:
        xray_process.terminate()
        try:
            xray_process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            xray_process.kill()
        logger.info("Xray stopped")
    xray_process = None


def restart_xray():
    stop_xray()
    return start_xray()


def is_xray_running() -> bool:
    return xray_process is not None and xray_process.poll() is None


def _generate_reality_keys():
    try:
        result = subprocess.run([str(XRAY_BIN), "x25519"], capture_output=True, text=True, timeout=10)
        logger.info(f"x25519 output: {result.stdout.strip()}")
        lines = result.stdout.strip().split("\n")
        priv = pub = ""
        for line in lines:
            low = line.lower()
            if "private" in low:
                priv = line.split(":")[-1].strip()
            elif "public" in low or "password" in low:
                pub = line.split(":")[-1].strip()
        if priv and pub:
            return priv, pub
        logger.error(f"x25519 parsing failed. stdout={result.stdout} stderr={result.stderr}")
        return "", ""
    except Exception as e:
        logger.error(f"x25519 failed: {e}")
        return "", ""


# ═══════════════════════════════════════════
#  LIFESPAN
# ═══════════════════════════════════════════

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    setup_admin()
    if XRAY_BIN.exists():
        conn = get_db()
        has = conn.execute("SELECT COUNT(*) as c FROM inbounds").fetchone()["c"] > 0
        conn.close()
        if has:
            start_xray()
    task = asyncio.create_task(_auto_disable_loop())
    yield
    task.cancel()
    stop_xray()


async def _auto_disable_loop():
    while True:
        try:
            await asyncio.sleep(60)
            _sync_traffic_from_xray()
            _check_and_disable_clients()
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"Auto-disable error: {e}")


def _xray_api_stats(pattern="", reset=True):
    api_port = int(get_setting("xray_api_port", "10085"))
    try:
        cmd = [str(XRAY_BIN), "api", "stats", f"--server=127.0.0.1:{api_port}"]
        if pattern:
            cmd.extend(["-pattern", pattern])
        if reset:
            cmd.append("-reset")
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if r.returncode != 0:
            return {}
        result = {}
        current_name = ""
        for line in r.stdout.strip().split("\n"):
            line = line.strip()
            if line.startswith("stat: <"):
                continue
            if line.startswith("name:"):
                current_name = line.split('"')[1] if '"' in line else ""
            elif line.startswith("value:") and current_name:
                try:
                    val = int(line.split(":")[1].strip())
                    result[current_name] = val
                except:
                    pass
                current_name = ""
        return result
    except Exception as e:
        logger.debug(f"Xray stats error: {e}")
        return {}


def _xray_api_online():
    api_port = int(get_setting("xray_api_port", "10085"))
    try:
        r = subprocess.run(
            [str(XRAY_BIN), "api", "stats", f"--server=127.0.0.1:{api_port}", "-pattern", "user>>>", "-reset=false"],
            capture_output=True, text=True, timeout=10
        )
        if r.returncode != 0:
            return []
        online = set()
        current_name = ""
        for line in r.stdout.strip().split("\n"):
            line = line.strip()
            if line.startswith("name:") and "user>>>" in line and ">>>traffic>>>" in line:
                parts = line.split(">>>")
                if len(parts) >= 2:
                    email = parts[1]
                    online.add(email)
        return list(online)
    except:
        return []


def _sync_traffic_from_xray():
    if not is_xray_running():
        return
    stats = _xray_api_stats("user>>>", reset=True)
    if not stats:
        return
    traffic = {}
    for name, value in stats.items():
        parts = name.split(">>>")
        if len(parts) == 4 and parts[0] == "user" and parts[2] == "traffic":
            email = parts[1]
            direction = parts[3]
            if email not in traffic:
                traffic[email] = {"up": 0, "down": 0}
            if direction == "uplink":
                traffic[email]["up"] = value
            elif direction == "downlink":
                traffic[email]["down"] = value
    if not traffic:
        return
    try:
        conn = get_db()
        for email, data in traffic.items():
            if data["up"] > 0 or data["down"] > 0:
                conn.execute(
                    "UPDATE clients SET upload=upload+?, download=download+? WHERE email=?",
                    (data["up"], data["down"], email)
                )
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Traffic sync error: {e}")


def _check_and_disable_clients():
    try:
        conn = get_db()
        now = int(datetime.now().timestamp() * 1000)
        changed = False
        clients = conn.execute("SELECT id, expiry_time, traffic_limit, upload, download, enabled FROM clients WHERE enabled=1").fetchall()
        for c in clients:
            disable = False
            if c["expiry_time"] and c["expiry_time"] > 0 and now > c["expiry_time"]:
                disable = True
            if c["traffic_limit"] and c["traffic_limit"] > 0:
                total = (c["upload"] or 0) + (c["download"] or 0)
                if total >= c["traffic_limit"]:
                    disable = True
            if disable:
                conn.execute("UPDATE clients SET enabled=0 WHERE id=?", (c["id"],))
                changed = True
                try:
                    _tg_send(f"⚠️ <b>Client disabled</b>\nID: <code>{c['id']}</code>\nReason: {'expired' if c['expiry_time'] and c['expiry_time'] > 0 and now > c['expiry_time'] else 'traffic limit'}")
                except:
                    pass
        if changed:
            conn.commit()
            restart_xray()
        conn.close()
    except Exception as e:
        logger.error(f"Auto-disable check error: {e}")


app = FastAPI(title="SelfRay-UI", lifespan=lifespan)
def _get_session_secret():
    try:
        s = get_setting("session_secret", "")
        if not s:
            s = secrets.token_hex(32)
            set_setting("session_secret", s)
        return s
    except:
        return secrets.token_hex(32)

init_db()
app.add_middleware(SessionMiddleware, secret_key=_get_session_secret())
app.mount("/static", StaticFiles(directory=str(APP_DIR / "static")), name="static")
templates = Jinja2Templates(directory=str(APP_DIR / "templates"))


def get_current_user(request: Request):
    user = request.session.get("user")
    if not user:
        raise HTTPException(status_code=401)
    return user


# ═══════════════════════════════════════════
#  AUTH ROUTES
# ═══════════════════════════════════════════

FAKE_SITES = [
    ("Apache2 Default", "<!DOCTYPE html><html><body><h1>It works!</h1><p>This is the default web page for this server.</p><p>The web server software is running but no content has been added, yet.</p></body></html>"),
    ("nginx Welcome", "<!DOCTYPE html><html><head><title>Welcome to nginx!</title></head><body><center><h1>Welcome to nginx!</h1></center><hr><center>nginx/1.24.0 (Ubuntu)</center></body></html>"),
    ("IIS Default", '<!DOCTYPE html><html><head><title>IIS Windows Server</title></head><body style="font-family:Segoe UI,Arial;margin:40px"><h1 style="color:#00599c">Internet Information Services</h1><p>Windows Server</p><hr style="color:#ccc"></body></html>'),
    ("403 Forbidden", "<!DOCTYPE html><html><head><title>403 Forbidden</title></head><body><center><h1>403 Forbidden</h1></center><hr><center>nginx</center></body></html>"),
    ("404 Not Found", "<!DOCTYPE html><html><head><title>404 Not Found</title></head><body><center><h1>404 Not Found</h1></center><hr><center>nginx/1.24.0</center></body></html>"),
    ("503 Unavailable", "<!DOCTYPE html><html><head><title>503 Service Temporarily Unavailable</title></head><body><center><h1>503 Service Temporarily Unavailable</h1></center><hr><center>nginx/1.24.0</center></body></html>"),
    ("502 Bad Gateway", "<!DOCTYPE html><html><head><title>502 Bad Gateway</title></head><body><center><h1>502 Bad Gateway</h1></center><hr><center>cloudflare</center></body></html>"),
    ("Blank", "<!DOCTYPE html><html><head><title></title></head><body></body></html>"),
    ("Under Construction", '<!DOCTYPE html><html><head><title>Site Under Construction</title><meta charset="utf-8"></head><body style="font-family:Arial,sans-serif;text-align:center;padding:80px;background:#fafafa"><div style="max-width:500px;margin:0 auto"><h1 style="font-size:48px;margin-bottom:8px">🚧</h1><h2 style="color:#333">Under Construction</h2><p style="color:#888">We\'re working on something awesome. Check back soon!</p><div style="margin-top:40px;height:4px;background:#eee;border-radius:2px"><div style="width:65%;height:100%;background:linear-gradient(90deg,#667eea,#764ba2);border-radius:2px"></div></div><p style="color:#aaa;font-size:12px;margin-top:8px">65% complete</p></div></body></html>'),
    ("Coming Soon", '<!DOCTYPE html><html><head><title>Coming Soon</title><meta charset="utf-8"></head><body style="font-family:Helvetica,Arial;text-align:center;padding:100px 20px;background:linear-gradient(135deg,#0f0c29,#302b63,#24243e);color:#fff;min-height:100vh;margin:0;box-sizing:border-box"><h1 style="font-size:42px;font-weight:300;letter-spacing:4px">COMING SOON</h1><p style="color:rgba(255,255,255,.6);font-size:16px;max-width:400px;margin:20px auto">Something amazing is being built. Stay tuned.</p><div style="margin-top:40px;display:flex;justify-content:center;gap:20px"><div style="text-align:center"><div style="font-size:32px;font-weight:700" id="d">12</div><div style="font-size:11px;color:rgba(255,255,255,.4)">DAYS</div></div><div style="text-align:center"><div style="font-size:32px;font-weight:700">08</div><div style="font-size:11px;color:rgba(255,255,255,.4)">HOURS</div></div><div style="text-align:center"><div style="font-size:32px;font-weight:700">45</div><div style="font-size:11px;color:rgba(255,255,255,.4)">MINUTES</div></div></div></body></html>'),
    ("Plesk Default", '<!DOCTYPE html><html><head><title>Default Web Page</title><meta charset="utf-8"></head><body style="font-family:Open Sans,Arial;background:#f7f7f7;margin:0;padding:40px"><div style="max-width:800px;margin:0 auto;background:#fff;padding:40px;border-radius:4px;box-shadow:0 1px 3px rgba(0,0,0,.1)"><h1 style="color:#333;border-bottom:1px solid #eee;padding-bottom:15px">Default Web Page</h1><p style="color:#666;line-height:1.6">This page is used to test the proper operation of the server after installation. If you can read this page, it means that the web server installed at this site is working properly.</p><h2 style="color:#555;margin-top:30px">For administrators</h2><p style="color:#666;line-height:1.6">You should add your website content to the web root directory. If you see this page instead of the site you expected, contact the server administrator.</p></div></body></html>'),
    ("cPanel Default", '<!DOCTYPE html><html><head><title>cPanel - Default Web Page</title></head><body style="font-family:Verdana;background:#eef1f6;margin:0;padding:40px"><div style="max-width:700px;margin:0 auto;background:#fff;padding:30px;border-top:4px solid #ff6c2c"><h1 style="color:#ff6c2c;font-size:22px">Great Success!</h1><p style="color:#555">The cPanel server is configured and working. This is the default page.</p><p style="color:#999;font-size:13px">If this is your website, log into your cPanel to begin.</p></div></body></html>'),
    ("WordPress Maintenance", '<!DOCTYPE html><html><head><title>Maintenance</title><meta charset="utf-8"></head><body style="font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,sans-serif;text-align:center;padding:100px 20px;background:#f0f0f0"><h1 style="font-size:28px;color:#23282d">Briefly unavailable for scheduled maintenance. Check back in a minute.</h1></body></html>'),
    ("Cloudflare Error", '<!DOCTYPE html><html><head><title>Attention Required! | Cloudflare</title></head><body style="font-family:sans-serif;text-align:center;padding:50px;background:#f8f8f8"><div style="max-width:600px;margin:0 auto"><h1 style="font-size:100px;color:#cf4a31;margin:0">⚠️</h1><h2 style="color:#333">Attention Required!</h2><p style="color:#666">This website is using a security service to protect itself from online attacks.</p><p style="color:#999;font-size:13px">Cloudflare Ray ID: '+secrets.token_hex(8)+'</p></div></body></html>'),
    ("DirectAdmin", '<!DOCTYPE html><html><head><title>DirectAdmin - Web Control Panel</title></head><body style="font-family:Tahoma;background:#e8ecf1;margin:0;padding:60px 20px"><div style="max-width:600px;margin:0 auto;text-align:center"><h1 style="color:#39455e;font-size:24px">Server Default Page</h1><p style="color:#778;line-height:1.8">If you are seeing this page, the web server is installed and working properly but has no content yet.</p><p style="color:#99a;font-size:12px;margin-top:30px">Powered by DirectAdmin</p></div></body></html>'),
    ("Parking Page", '<!DOCTYPE html><html><head><title>Domain Parking</title><meta charset="utf-8"></head><body style="font-family:Arial;text-align:center;padding:80px 20px;background:#fff"><h1 style="color:#222;font-weight:400;font-size:26px">This domain is parked</h1><p style="color:#999;max-width:500px;margin:15px auto">This domain has been registered and is currently not associated with any website. If you are the owner, please configure your hosting.</p><hr style="border:none;border-top:1px solid #eee;margin:40px auto;max-width:200px"><p style="color:#ccc;font-size:11px">Domain parking by registrar</p></body></html>'),
    ("GitLab Maintenance", '<!DOCTYPE html><html><head><title>Deploy in progress</title></head><body style="font-family:Source Sans Pro,sans-serif;text-align:center;padding:100px 20px;background:#292961;color:#fff;margin:0"><div style="max-width:500px;margin:0 auto"><h1 style="font-weight:400;font-size:28px">Deploy in progress</h1><p style="color:rgba(255,255,255,.6)">This GitLab instance is being updated. It will be back shortly.</p></div></body></html>'),
    ("Heroku No App", '<!DOCTYPE html><html><head><title>Heroku | No such app</title></head><body style="font-family:sans-serif;text-align:center;padding:80px;background:#f5f5f5"><h1 style="color:#5e514d">There is no app configured at this address.</h1><p style="color:#999">If you are the application owner, check your logs for details.</p></body></html>'),
    ("Caddy Default", '<!DOCTYPE html><html><head><title>Caddy - Default Page</title></head><body style="font-family:system-ui;text-align:center;padding:60px;background:#fff"><h1 style="color:#00727a;font-weight:500">Caddy is running!</h1><p style="color:#777;max-width:450px;margin:10px auto">This page was delivered by <strong>Caddy</strong> web server. Replace this page with your own content.</p></body></html>'),
    ("LiteSpeed Default", '<!DOCTYPE html><html><head><title>LiteSpeed Web Server</title></head><body style="font-family:Lucida Grande,Arial;text-align:center;padding:80px;background:#fafafa"><h1 style="color:#222;font-size:30px">LiteSpeed Web Server</h1><p style="color:#888">Your server is up and running.</p><p style="color:#bbb;font-size:12px;margin-top:40px">LiteSpeed Technologies</p></body></html>'),
]

_fake_page = None

def _get_fake_page():
    global _fake_page
    mode = get_setting("fake_site_mode", "random")
    if mode == "off":
        return None
    if mode == "fixed" and _fake_page is not None:
        return _fake_page
    _fake_page = _rnd.choice(FAKE_SITES)
    return _fake_page


@app.get("/", response_class=HTMLResponse)
async def root(request: Request):
    if request.session.get("user"):
        return RedirectResponse("/panel", status_code=302)
    fake = _get_fake_page()
    if fake:
        _, html = fake
        return HTMLResponse(html)
    return RedirectResponse("/login", status_code=302)


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    totp_on = get_setting("totp_enabled", "false") == "true"
    return templates.TemplateResponse("login.html", {"request": request, "totp_required": totp_on})


@app.post("/login")
async def login(request: Request, username: str = Form(...), password: str = Form(...), totp_code: str = Form("")):
    conn = get_db()
    user = conn.execute(
        "SELECT * FROM users WHERE username=? AND password_hash=?",
        (username, hash_password(password))
    ).fetchone()
    conn.close()
    if not user:
        return templates.TemplateResponse("login.html", {"request": request, "error": "Wrong login or password"})
    if get_setting("totp_enabled", "false") == "true":
        try:
            import pyotp
            secret = get_setting("totp_secret", "")
            if secret:
                totp = pyotp.TOTP(secret)
                if not totp.verify(totp_code or ""):
                    return templates.TemplateResponse("login.html", {"request": request, "error": "Invalid 2FA code", "totp_required": True})
        except ImportError:
            pass
    request.session["user"] = username
    if get_setting("tg_notify_login", "true") == "true":
        client_ip = request.client.host if request.client else "unknown"
        _tg_send(f"🔐 <b>Panel Login</b>\nUser: <code>{username}</code>\nIP: <code>{client_ip}</code>\nTime: {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    return RedirectResponse("/panel", status_code=302)


@app.get("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login", status_code=302)


@app.get("/panel", response_class=HTMLResponse)
async def panel(request: Request, user: str = Depends(get_current_user)):
    return templates.TemplateResponse("panel.html", {"request": request, "user": user})


# ═══════════════════════════════════════════
#  API: STATUS
# ═══════════════════════════════════════════

@app.get("/api/status")
async def api_status(request: Request, user: str = Depends(get_current_user)):
    uptime = 0
    try:
        with open("/proc/uptime") as f:
            uptime = int(float(f.read().split()[0]))
    except:
        pass
    try:
        server_ip = _get_server_ip(request)
    except:
        server_ip = ""
    real_ip = _get_real_ip()
    online = _xray_api_online() if is_xray_running() else []
    return {
        "xray_running": is_xray_running(),
        "xray_installed": XRAY_BIN.exists(),
        "pid": xray_process.pid if is_xray_running() else None,
        "uptime": uptime,
        "server_ip": server_ip,
        "real_ip": real_ip,
        "online_users": online,
        "online_count": len(online)
    }


def _get_server_ip(request: Request = None):
    if request:
        host = request.headers.get("host", "").split(":")[0]
        if host and host not in ("0.0.0.0", "127.0.0.1", "localhost"):
            return host
    return _get_real_ip()


def _get_real_ip():
    try:
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        pass
    try:
        r = subprocess.run(["curl", "-s4", "--max-time", "5", "ifconfig.me"],
                           capture_output=True, text=True, timeout=10)
        if r.returncode == 0 and r.stdout.strip():
            return r.stdout.strip()
    except:
        pass
    return ""


# ═══════════════════════════════════════════
#  API: XRAY CONTROL
# ═══════════════════════════════════════════

@app.post("/api/xray/start")
async def api_xray_start(user: str = Depends(get_current_user)):
    return {"success": start_xray()}

@app.post("/api/xray/stop")
async def api_xray_stop(user: str = Depends(get_current_user)):
    stop_xray()
    return {"success": True}

@app.post("/api/xray/restart")
async def api_xray_restart(user: str = Depends(get_current_user)):
    return {"success": restart_xray()}

@app.get("/api/xray/config")
async def api_xray_config(user: str = Depends(get_current_user)):
    if XRAY_CONFIG_PATH.exists():
        return json.loads(XRAY_CONFIG_PATH.read_text())
    return {}

@app.get("/api/xray/version")
async def api_xray_version(user: str = Depends(get_current_user)):
    if not XRAY_BIN.exists():
        return {"installed": False}
    try:
        r = subprocess.run([str(XRAY_BIN), "version"], capture_output=True, text=True, timeout=10)
        ver = r.stdout.split("\n")[0] if r.stdout else "unknown"
        parts = ver.split()
        if len(parts) >= 2:
            ver = parts[1]
        return {"installed": True, "version": ver}
    except:
        return {"installed": True, "version": "unknown"}

@app.post("/api/xray/install")
async def api_install_xray(user: str = Depends(get_current_user)):
    XRAY_DIR.mkdir(parents=True, exist_ok=True)
    arch = platform.machine()
    arch_map = {"x86_64": "64", "amd64": "64", "aarch64": "arm64-v8a", "arm64": "arm64-v8a", "armv7l": "arm32-v7a"}
    xray_arch = arch_map.get(arch, "64")
    try:
        cmd = f"cd /tmp && wget -q https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-{xray_arch}.zip -O xray.zip && unzip -o xray.zip -d {XRAY_DIR} && chmod +x {XRAY_BIN} && rm -f xray.zip"
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=120)
        if r.returncode != 0:
            return {"success": False, "error": r.stderr}
        vr = subprocess.run([str(XRAY_BIN), "version"], capture_output=True, text=True, timeout=10)
        return {"success": True, "version": vr.stdout.split("\n")[0] if vr.returncode == 0 else "installed"}
    except Exception as e:
        return {"success": False, "error": str(e)}


# ═══════════════════════════════════════════
#  API: SETTINGS
# ═══════════════════════════════════════════

@app.get("/api/settings")
async def api_get_settings(user: str = Depends(get_current_user)):
    return {
        "panel_port": int(get_setting("panel_port", "8443")),
        "panel_host": get_setting("panel_host", "0.0.0.0"),
        "panel_path": get_setting("panel_path", "/"),
        "xray_api_port": int(get_setting("xray_api_port", "10085")),
        "xray_log_level": get_setting("xray_log_level", "warning"),
        "sub_enable": get_setting("sub_enable", "true") == "true",
        "sub_port": int(get_setting("sub_port", "2096")),
        "sub_path": get_setting("sub_path", "/sub"),
        "block_bittorrent": get_setting("block_bittorrent", "true") == "true",
        "custom_dns": get_setting("custom_dns", ""),
        "custom_routing_rules": get_setting("custom_routing_rules", ""),
        "tg_bot_token": get_setting("tg_bot_token", ""),
        "tg_chat_id": get_setting("tg_chat_id", ""),
        "tg_notify_login": get_setting("tg_notify_login", "true") == "true",
        "tg_notify_expiry": get_setting("tg_notify_expiry", "true") == "true",
        "tg_notify_traffic": get_setting("tg_notify_traffic", "true") == "true",
        "warp_mode": get_setting("warp_mode", "off"),
        "warp_license_key": get_setting("warp_license_key", ""),
        "warp_domains": get_setting("warp_domains", "geosite:openai, geosite:netflix, geosite:google, geosite:spotify, chatgpt.com, disney.com"),
        "fake_site_mode": get_setting("fake_site_mode", "random"),
    }


class SettingsUpdate(BaseModel):
    panel_port: Optional[int] = None
    panel_host: Optional[str] = None
    panel_path: Optional[str] = None
    xray_api_port: Optional[int] = None
    xray_log_level: Optional[str] = None
    sub_enable: Optional[bool] = None
    sub_port: Optional[int] = None
    sub_path: Optional[str] = None
    block_bittorrent: Optional[bool] = None
    custom_dns: Optional[str] = None
    custom_routing_rules: Optional[str] = None
    tg_bot_token: Optional[str] = None
    tg_chat_id: Optional[str] = None
    tg_notify_login: Optional[bool] = None
    tg_notify_expiry: Optional[bool] = None
    tg_notify_traffic: Optional[bool] = None
    fake_site_mode: Optional[str] = None


@app.post("/api/settings")
async def api_update_settings(data: SettingsUpdate, user: str = Depends(get_current_user)):
    fields = {
        "panel_port": str, "panel_host": str, "panel_path": str,
        "xray_api_port": str, "xray_log_level": str,
        "sub_port": str, "sub_path": str, "custom_dns": str,
        "custom_routing_rules": str
    }
    for k, conv in fields.items():
        v = getattr(data, k, None)
        if v is not None:
            set_setting(k, conv(v))
    if data.sub_enable is not None:
        set_setting("sub_enable", "true" if data.sub_enable else "false")
    if data.block_bittorrent is not None:
        set_setting("block_bittorrent", "true" if data.block_bittorrent else "false")
    if data.tg_bot_token is not None:
        set_setting("tg_bot_token", data.tg_bot_token)
    if data.tg_chat_id is not None:
        set_setting("tg_chat_id", data.tg_chat_id)
    for k in ("tg_notify_login", "tg_notify_expiry", "tg_notify_traffic"):
        v = getattr(data, k, None)
        if v is not None:
            set_setting(k, "true" if v else "false")
    if data.fake_site_mode is not None:
        set_setting("fake_site_mode", data.fake_site_mode)
        global _fake_page
        _fake_page = None
    return {"success": True, "note": "Restart xray to apply xray-related changes"}


class PasswordChange(BaseModel):
    old_password: str
    new_password: str

@app.post("/api/change-password")
async def api_change_password(data: PasswordChange, user: str = Depends(get_current_user)):
    conn = get_db()
    row = conn.execute("SELECT * FROM users WHERE username=? AND password_hash=?",
                       (user, hash_password(data.old_password))).fetchone()
    if not row:
        conn.close()
        raise HTTPException(400, "Wrong old password")
    conn.execute("UPDATE users SET password_hash=? WHERE username=?", (hash_password(data.new_password), user))
    conn.commit()
    conn.close()
    return {"success": True}



# ═══════════════════════════════════════════
#  API: SSL CERTIFICATE
# ═══════════════════════════════════════════

CERT_DIR = DATA_DIR / "cert"

def _get_cert_info():
    cert_file = CERT_DIR / "fullchain.pem"
    key_file = CERT_DIR / "privkey.pem"
    if not cert_file.exists() or not key_file.exists():
        return {"installed": False}
    try:
        r = subprocess.run(
            ["openssl", "x509", "-in", str(cert_file), "-noout", "-subject", "-issuer", "-dates", "-fingerprint"],
            capture_output=True, text=True, timeout=10
        )
        if r.returncode != 0:
            return {"installed": True, "error": r.stderr}
        info = {"installed": True, "cert_path": str(cert_file), "key_path": str(key_file)}
        for line in r.stdout.strip().split("\n"):
            if line.startswith("subject="):
                info["subject"] = line.split("=", 1)[1].strip()
            elif line.startswith("issuer="):
                info["issuer"] = line.split("=", 1)[1].strip()
            elif line.startswith("notBefore="):
                info["not_before"] = line.split("=", 1)[1].strip()
            elif line.startswith("notAfter="):
                info["not_after"] = line.split("=", 1)[1].strip()
            elif "Fingerprint" in line:
                info["fingerprint"] = line.split("=", 1)[1].strip()
        is_self = info.get("subject", "") == info.get("issuer", "")
        info["type"] = "self-signed" if is_self else "CA-signed"
        return info
    except Exception as e:
        return {"installed": True, "error": str(e)}


@app.get("/api/cert/status")
async def api_cert_status(user: str = Depends(get_current_user)):
    info = _get_cert_info()
    info["domain"] = get_setting("ssl_domain", "")
    return info


@app.post("/api/cert/self-signed")
async def api_cert_self_signed(user: str = Depends(get_current_user)):
    CERT_DIR.mkdir(parents=True, exist_ok=True)
    cert_file = CERT_DIR / "fullchain.pem"
    key_file = CERT_DIR / "privkey.pem"
    try:
        ip = ""
        try:
            r = subprocess.run(["curl", "-s4", "--max-time", "5", "ifconfig.me"],
                               capture_output=True, text=True, timeout=10)
            if r.returncode == 0:
                ip = r.stdout.strip()
        except:
            pass
        san = f"IP:{ip}" if ip else "DNS:localhost"
        cmd = [
            "openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
            "-keyout", str(key_file), "-out", str(cert_file),
            "-days", "3650", "-nodes",
            "-subj", f"/CN=SelfRay-UI",
            "-addext", f"subjectAltName={san},DNS:localhost,IP:127.0.0.1"
        ]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if r.returncode != 0:
            return {"success": False, "error": r.stderr}
        set_setting("ssl_cert_path", str(cert_file))
        set_setting("ssl_key_path", str(key_file))
        set_setting("ssl_enabled", "true")
        return {"success": True, "message": "Self-signed certificate generated (10 years). Restart panel to apply HTTPS."}
    except Exception as e:
        return {"success": False, "error": str(e)}


@app.post("/api/cert/acme")
async def api_cert_acme(request: Request, user: str = Depends(get_current_user)):
    body = await request.json()
    domain = body.get("domain", "").strip()
    email = body.get("email", "").strip()
    if not domain:
        return {"success": False, "error": "Domain is required"}
    r = subprocess.run(["which", "certbot"], capture_output=True, text=True)
    if r.returncode != 0:
        try:
            subprocess.run(["apt-get", "install", "-y", "-qq", "certbot"], capture_output=True, text=True, timeout=120)
        except:
            return {"success": False, "error": "Failed to install certbot"}
    CERT_DIR.mkdir(parents=True, exist_ok=True)
    try:
        cmd = [
            "certbot", "certonly", "--standalone",
            "--preferred-challenges", "http",
            "--http-01-port", "80",
            "-d", domain,
            "--agree-tos", "--non-interactive",
            "--keep-until-expiring",
        ]
        if email:
            cmd += ["--email", email]
        else:
            cmd += ["--register-unsafely-without-email"]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if r.returncode != 0:
            err = (r.stderr or r.stdout or "certbot failed")[-500:]
            return {"success": False, "error": err}
        le_cert = Path(f"/etc/letsencrypt/live/{domain}/fullchain.pem")
        le_key = Path(f"/etc/letsencrypt/live/{domain}/privkey.pem")
        if le_cert.exists() and le_key.exists():
            import shutil as _sh
            _sh.copy2(str(le_cert), str(CERT_DIR / "fullchain.pem"))
            _sh.copy2(str(le_key), str(CERT_DIR / "privkey.pem"))
        else:
            return {"success": False, "error": f"Certificate files not found at {le_cert}"}
        set_setting("ssl_cert_path", str(CERT_DIR / "fullchain.pem"))
        set_setting("ssl_key_path", str(CERT_DIR / "privkey.pem"))
        set_setting("ssl_enabled", "true")
        set_setting("ssl_domain", domain)
        return {"success": True, "message": f"Certificate issued for {domain}. Panel will restart now.", "restart": True}
    except Exception as e:
        return {"success": False, "error": str(e)}


@app.post("/api/cert/revoke")
async def api_cert_revoke(user: str = Depends(get_current_user)):
    cert_file = CERT_DIR / "fullchain.pem"
    key_file = CERT_DIR / "privkey.pem"
    try:
        if cert_file.exists():
            cert_file.unlink()
        if key_file.exists():
            key_file.unlink()
        set_setting("ssl_cert_path", "")
        set_setting("ssl_key_path", "")
        set_setting("ssl_enabled", "false")
        return {"success": True, "message": "Certificate removed. Restart panel to switch to HTTP."}
    except Exception as e:
        return {"success": False, "error": str(e)}


# ═══════════════════════════════════════════
#  API: INBOUNDS
# ═══════════════════════════════════════════

class InboundCreate(BaseModel):
    protocol: str
    port: int
    listen: str = ""
    remark: str = ""
    # Stream
    network: str = "tcp"
    security: str = "none"
    # TLS
    tls_server_name: str = ""
    tls_cert_file: str = ""
    tls_key_file: str = ""
    tls_alpn: str = "h2,http/1.1"
    tls_fingerprint: str = "chrome"
    # Reality
    reality_dest: str = "google.com:443"
    reality_server_names: str = "google.com"
    reality_private_key: str = ""
    reality_public_key: str = ""
    reality_short_ids: str = ""
    reality_spider_x: str = ""
    reality_fingerprint: str = "chrome"
    # VLESS
    flow: str = ""
    vless_decryption: str = "none"
    # VMess
    vmess_alter_id: int = 0
    # Trojan
    trojan_fallback_addr: str = ""
    trojan_fallback_port: int = 0
    # Shadowsocks
    ss_method: str = "chacha20-ietf-poly1305"
    ss_password: str = ""
    ss_network: str = "tcp,udp"
    # TCP
    tcp_header_type: str = "none"
    tcp_header_request_path: str = "/"
    tcp_header_request_host: str = ""
    # WebSocket
    ws_path: str = "/ws"
    ws_host: str = ""
    # gRPC
    grpc_service_name: str = ""
    grpc_multi_mode: bool = False
    # HTTP/2
    h2_path: str = "/"
    h2_host: str = ""
    # HTTPUPGRADE
    httpupgrade_path: str = "/"
    httpupgrade_host: str = ""
    # XHTTP
    xhttp_path: str = "/"
    xhttp_host: str = ""
    xhttp_mode: str = "auto"
    # Sniffing
    sniffing_enabled: bool = True
    sniffing_dest_override: str = "http,tls,quic"
    sniffing_route_only: bool = False
    # First client
    client_name: str = ""
    first_client_traffic_gb: float = 0
    country: str = ""


@app.get("/api/inbounds")
async def api_list_inbounds(user: str = Depends(get_current_user)):
    conn = get_db()
    rows = conn.execute("SELECT * FROM inbounds ORDER BY id").fetchall()
    result = []
    for r in rows:
        clients = conn.execute("SELECT * FROM clients WHERE inbound_id=?", (r["id"],)).fetchall()
        result.append({**dict(r), "clients": [dict(c) for c in clients]})
    conn.close()
    return result


@app.get("/api/inbounds/{inbound_id}")
async def api_get_inbound(inbound_id: int, user: str = Depends(get_current_user)):
    conn = get_db()
    row = conn.execute("SELECT * FROM inbounds WHERE id=?", (inbound_id,)).fetchone()
    if not row:
        conn.close()
        raise HTTPException(404)
    clients = conn.execute("SELECT * FROM clients WHERE inbound_id=?", (inbound_id,)).fetchall()
    conn.close()
    return {**dict(row), "clients": [dict(c) for c in clients]}


def core_create_inbound(protocol, port, listen="", remark="", network="tcp", security="none", flow="", client_name="", country="", **kwargs):
    data = InboundCreate(
        protocol=protocol, port=port, listen=listen, remark=remark,
        network=network, security=security, flow=flow, client_name=client_name, country=country,
        **{k: v for k, v in kwargs.items() if k in InboundCreate.__fields__}
    )
    if data.security == "reality" and not data.reality_private_key and not data.reality_public_key:
        if not XRAY_BIN.exists():
            return {"success": False, "error": "Install Xray first (need xray x25519)"}
        priv, pub = _generate_reality_keys()
        if not priv or not pub:
            return {"success": False, "error": "Failed to generate Reality keys"}
        data.reality_private_key = priv
        data.reality_public_key = pub

    tag = f"{data.protocol}-{data.port}-{secrets.token_hex(3)}"
    settings = _build_protocol_settings(data)
    stream = _build_stream_settings(data)
    sniffing = {
        "enabled": data.sniffing_enabled,
        "destOverride": [s.strip() for s in data.sniffing_dest_override.split(",") if s.strip()]
    }
    if data.sniffing_route_only:
        sniffing["routeOnly"] = True

    conn = get_db()
    rm = data.remark
    if data.country:
        rm = f"{data.country} {rm}".strip() if rm else data.country
    try:
        conn.execute(
            "INSERT INTO inbounds (tag, protocol, listen, port, settings, stream_settings, sniffing, remark) VALUES (?,?,?,?,?,?,?,?)",
            (tag, data.protocol, data.listen, data.port, json.dumps(settings), json.dumps(stream), json.dumps(sniffing), rm)
        )
        conn.commit()
        inbound_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    except sqlite3.IntegrityError:
        conn.close()
        return {"success": False, "error": f"Tag conflict: {tag}"}

    link = ""
    if data.protocol != "shadowsocks":
        client_uuid = str(uuid.uuid4())
        client_id = secrets.token_hex(8)
        cname = data.client_name or "default-user"
        traffic_limit = int(data.first_client_traffic_gb * 1024 * 1024 * 1024) if data.first_client_traffic_gb > 0 else 0
        conn.execute(
            "INSERT INTO clients (id, inbound_id, email, uuid, flow, traffic_limit) VALUES (?,?,?,?,?,?)",
            (client_id, inbound_id, cname, client_uuid, data.flow if data.protocol == "vless" else "", traffic_limit)
        )
        conn.commit()
    else:
        client_id = secrets.token_hex(8)
        cname = data.client_name or "default-user"
        ss_pass = data.ss_password or secrets.token_urlsafe(16)
        traffic_limit = int(data.first_client_traffic_gb * 1024 * 1024 * 1024) if data.first_client_traffic_gb > 0 else 0
        conn.execute(
            "INSERT INTO clients (id, inbound_id, email, uuid, flow, traffic_limit) VALUES (?,?,?,?,?,?)",
            (client_id, inbound_id, cname, ss_pass, "", traffic_limit)
        )
        conn.commit()

    try:
        ib_row = conn.execute("SELECT * FROM inbounds WHERE id=?", (inbound_id,)).fetchone()
        cl_row = conn.execute("SELECT * FROM clients WHERE id=?", (client_id,)).fetchone()
        if ib_row and cl_row:
            link = _generate_link(ib_row["protocol"], dict(cl_row), dict(ib_row),
                                  json.loads(ib_row["stream_settings"]), json.loads(ib_row["settings"]),
                                  ib_row["listen"] or "SERVER_IP")
    except:
        pass

    conn.close()
    if not kwargs.get("_skip_restart"):
        restart_xray()
    return {"success": True, "id": inbound_id, "link": link}


@app.post("/api/inbounds")
async def api_create_inbound(data: InboundCreate, user: str = Depends(get_current_user)):
    result = core_create_inbound(**data.dict())
    if not result.get("success"):
        raise HTTPException(400, result.get("error", "Failed"))
    return result


import random as _rnd

AUTOGEN_CONFIGS = [
    {"protocol": "vless", "network": "tcp", "security": "reality", "flow": "xtls-rprx-vision"},
    {"protocol": "vless", "network": "tcp", "security": "reality", "flow": "xtls-rprx-vision"},
    {"protocol": "vless", "network": "grpc", "security": "reality", "flow": ""},
    {"protocol": "vless", "network": "xhttp", "security": "reality", "flow": ""},
    {"protocol": "vless", "network": "grpc", "security": "reality", "flow": ""},
    {"protocol": "trojan", "network": "tcp", "security": "reality", "flow": ""},
    {"protocol": "trojan", "network": "grpc", "security": "reality", "flow": ""},
    {"protocol": "vmess", "network": "ws", "security": "none", "flow": ""},
    {"protocol": "vmess", "network": "tcp", "security": "none", "flow": ""},
    {"protocol": "shadowsocks", "network": "tcp", "security": "none", "flow": ""},
]

REALITY_DESTS = [
    "google.com:443", "microsoft.com:443", "apple.com:443",
    "cloudflare.com:443", "yahoo.com:443", "mozilla.org:443",
    "www.samsung.com:443", "www.cisco.com:443", "www.oracle.com:443",
    "www.tesla.com:443", "github.com:443", "www.wikipedia.org:443",
]

UTLS_FPS = ["chrome", "firefox", "safari", "edge", "random", "randomized"]


def _load_whitelist_domains():
    wl_file = APP_DIR / "static" / "whitelist-ru.txt"
    if not wl_file.exists():
        return REALITY_DESTS
    try:
        lines = wl_file.read_text().strip().split("\n")
        domains = [l.strip() for l in lines if l.strip() and not l.startswith("#")]
        good = [d for d in domains if "." in d and " " not in d and len(d) < 100]
        return good if good else REALITY_DESTS
    except:
        return REALITY_DESTS


@app.post("/api/inbounds/delete-auto")
async def api_delete_auto_inbounds(user: str = Depends(get_current_user)):
    try:
        conn = get_db()
        rows = conn.execute("SELECT id FROM inbounds WHERE remark LIKE 'auto-%'").fetchall()
        if not rows:
            conn.close()
            return {"success": True, "deleted": 0}
        ids = [r["id"] for r in rows]
        for ib_id in ids:
            conn.execute("UPDATE inbounds SET enabled=0 WHERE id=?", (ib_id,))
        conn.commit()
        for ib_id in ids:
            conn.execute("DELETE FROM clients WHERE inbound_id=?", (ib_id,))
            conn.execute("DELETE FROM inbounds WHERE id=?", (ib_id,))
        conn.commit()
        conn.close()
        restart_xray()
        return {"success": True, "deleted": len(ids)}
    except Exception as e:
        return {"success": False, "error": str(e)}


@app.post("/api/inbounds/auto-generate")
async def api_auto_generate(user: str = Depends(get_current_user)):
    if not XRAY_BIN.exists():
        return {"success": False, "error": "Install Xray first"}

    server_ip = _get_real_ip()
    if not server_ip:
        return {"success": False, "error": "Cannot detect server IP"}

    used_ports = set()
    conn = get_db()
    existing = conn.execute("SELECT port FROM inbounds").fetchall()
    conn.close()
    for r in existing:
        used_ports.add(r["port"])
    used_ports.add(int(get_setting("panel_port", "8443")))
    used_ports.add(int(get_setting("xray_api_port", "10085")))

    results = []
    configs = list(AUTOGEN_CONFIGS)
    _rnd.shuffle(configs)

    fixed_ports = [443, 8443]
    for cfg in configs[:10]:
        port = None
        if fixed_ports:
            p = fixed_ports.pop(0)
            if p not in used_ports:
                port = p
        if port is None:
            for _ in range(100):
                port = _rnd.randint(10000, 60000)
                if port not in used_ports:
                    break
        used_ports.add(port)

        kwargs = {
            "protocol": cfg["protocol"],
            "port": port,
            "listen": server_ip,
            "network": cfg["network"],
            "security": cfg["security"],
            "flow": cfg["flow"],
            "client_name": "auto-user",
            "remark": f"auto-{cfg['protocol']}-{cfg['network']}-{port}",
        }

        if cfg["security"] == "reality":
            dest_domain = _rnd.choice(REALITY_DESTS)
            sni = dest_domain.split(":")[0]
            kwargs["reality_dest"] = dest_domain
            kwargs["reality_server_names"] = sni
            kwargs["reality_fingerprint"] = "chrome"
        elif cfg["protocol"] == "shadowsocks":
            kwargs["ss_method"] = "chacha20-ietf-poly1305"
            kwargs["ss_password"] = secrets.token_urlsafe(16)

        if cfg["network"] == "ws":
            kwargs["ws_path"] = "/" + secrets.token_hex(4)
        elif cfg["network"] == "grpc":
            kwargs["grpc_service_name"] = secrets.token_hex(4)
        elif cfg["network"] == "httpupgrade":
            kwargs["httpupgrade_path"] = "/" + secrets.token_hex(4)
        elif cfg["network"] == "xhttp":
            kwargs["xhttp_path"] = "/" + secrets.token_hex(4)

        try:
            kwargs["_skip_restart"] = True
            r = core_create_inbound(**kwargs)
            results.append({"port": port, "success": r.get("success", False), "id": r.get("id"), "error": r.get("error")})
        except Exception as e:
            results.append({"port": port, "success": False, "error": str(e)})

    restart_xray()
    ok = sum(1 for r in results if r["success"])
    return {"success": True, "generated": ok, "total": len(results), "details": results}


class InboundUpdate(BaseModel):
    listen: Optional[str] = None
    port: Optional[int] = None
    remark: Optional[str] = None
    settings: Optional[str] = None
    stream_settings: Optional[str] = None
    sniffing: Optional[str] = None


@app.put("/api/inbounds/{inbound_id}")
async def api_update_inbound(inbound_id: int, data: InboundUpdate, user: str = Depends(get_current_user)):
    conn = get_db()
    row = conn.execute("SELECT * FROM inbounds WHERE id=?", (inbound_id,)).fetchone()
    if not row:
        conn.close()
        raise HTTPException(404)
    updates = []
    params = []
    if data.listen is not None:
        updates.append("listen=?"); params.append(data.listen)
    if data.port is not None:
        updates.append("port=?"); params.append(data.port)
    if data.remark is not None:
        updates.append("remark=?"); params.append(data.remark)
    if data.settings is not None:
        updates.append("settings=?"); params.append(data.settings)
    if data.stream_settings is not None:
        updates.append("stream_settings=?"); params.append(data.stream_settings)
    if data.sniffing is not None:
        updates.append("sniffing=?"); params.append(data.sniffing)
    if updates:
        updates.append("updated_at=datetime('now')")
        params.append(inbound_id)
        conn.execute(f"UPDATE inbounds SET {', '.join(updates)} WHERE id=?", params)
        conn.commit()
    conn.close()
    restart_xray()
    return {"success": True}


@app.delete("/api/inbounds/{inbound_id}")
async def api_delete_inbound(inbound_id: int, user: str = Depends(get_current_user)):
    conn = get_db()
    conn.execute("DELETE FROM clients WHERE inbound_id=?", (inbound_id,))
    conn.execute("DELETE FROM inbounds WHERE id=?", (inbound_id,))
    conn.commit()
    conn.close()
    restart_xray()
    return {"success": True}


@app.put("/api/inbounds/{inbound_id}/toggle")
async def api_toggle_inbound(inbound_id: int, user: str = Depends(get_current_user)):
    conn = get_db()
    row = conn.execute("SELECT enabled FROM inbounds WHERE id=?", (inbound_id,)).fetchone()
    if not row:
        conn.close()
        raise HTTPException(404)
    new = 0 if row["enabled"] else 1
    conn.execute("UPDATE inbounds SET enabled=? WHERE id=?", (new, inbound_id))
    conn.commit()
    conn.close()
    restart_xray()
    return {"success": True, "enabled": bool(new)}


@app.get("/api/inbounds/{inbound_id}")
async def api_get_inbound(inbound_id: int, user: str = Depends(get_current_user)):
    conn = get_db()
    row = conn.execute("SELECT * FROM inbounds WHERE id=?", (inbound_id,)).fetchone()
    conn.close()
    if not row:
        raise HTTPException(404)
    ib = dict(row)
    ib["stream_settings_parsed"] = json.loads(ib["stream_settings"])
    ib["settings_parsed"] = json.loads(ib["settings"])
    ib["sniffing_parsed"] = json.loads(ib["sniffing"]) if ib.get("sniffing") else {}
    return ib


@app.put("/api/inbounds/{inbound_id}")
async def api_edit_inbound(inbound_id: int, data: InboundCreate, user: str = Depends(get_current_user)):
    conn = get_db()
    row = conn.execute("SELECT * FROM inbounds WHERE id=?", (inbound_id,)).fetchone()
    if not row:
        conn.close()
        raise HTTPException(404)

    settings = _build_protocol_settings(data)
    stream = _build_stream_settings(data)
    sniffing = {"enabled": data.sniffing_enabled}
    if data.sniffing_dest_override:
        sniffing["destOverride"] = [x.strip() for x in data.sniffing_dest_override.split(",") if x.strip()]
    if data.sniffing_route_only:
        sniffing["routeOnly"] = True

    clients_rows = conn.execute("SELECT * FROM clients WHERE inbound_id=?", (inbound_id,)).fetchall()
    if data.protocol in ("vless", "vmess"):
        settings["clients"] = []
        for c in clients_rows:
            cl = {"id": c["uuid"], "email": c["email"]}
            if data.protocol == "vless" and c["flow"]:
                cl["flow"] = c["flow"]
            if data.protocol == "vmess":
                cl["alterId"] = 0
            settings["clients"].append(cl)
    elif data.protocol == "trojan":
        settings["clients"] = []
        for c in clients_rows:
            settings["clients"].append({"password": c["uuid"], "email": c["email"]})

    conn.execute("""UPDATE inbounds SET protocol=?, port=?, listen=?, settings=?, stream_settings=?,
        sniffing=?, remark=? WHERE id=?""",
        (data.protocol, data.port, data.listen, json.dumps(settings), json.dumps(stream),
         json.dumps(sniffing), data.remark, inbound_id))
    conn.commit()
    conn.close()
    restart_xray()
    return {"success": True}


def _build_protocol_settings(data: InboundCreate) -> dict:
    if data.protocol == "vless":
        s = {"clients": [], "decryption": data.vless_decryption or "none"}
        if data.security == "reality" and data.flow:
            s["flow"] = data.flow
        fallbacks = []
        if fallbacks:
            s["fallbacks"] = fallbacks
        return s
    elif data.protocol == "vmess":
        return {"clients": []}
    elif data.protocol == "trojan":
        s = {"clients": []}
        if data.trojan_fallback_addr:
            s["fallbacks"] = [{"addr": data.trojan_fallback_addr, "port": data.trojan_fallback_port or 80}]
        return s
    elif data.protocol == "shadowsocks":
        return {
            "method": data.ss_method,
            "password": data.ss_password or secrets.token_urlsafe(16),
            "network": data.ss_network
        }
    return {}


def _build_stream_settings(data: InboundCreate) -> dict:
    stream = {"network": data.network, "security": data.security}

    # ── TCP ──
    if data.network == "tcp":
        tcp = {"header": {"type": data.tcp_header_type}}
        if data.tcp_header_type == "http":
            tcp["header"]["request"] = {
                "path": [data.tcp_header_request_path or "/"],
                "headers": {"Host": [data.tcp_header_request_host] if data.tcp_header_request_host else []}
            }
        stream["tcpSettings"] = tcp

    # ── WebSocket ──
    elif data.network == "ws":
        ws = {"path": data.ws_path or "/ws"}
        if data.ws_host:
            ws["headers"] = {"Host": data.ws_host}
        stream["wsSettings"] = ws

    # ── gRPC ──
    elif data.network == "grpc":
        stream["grpcSettings"] = {
            "serviceName": data.grpc_service_name or "grpc",
            "multiMode": data.grpc_multi_mode
        }

    # ── HTTP/2 ──
    elif data.network == "h2":
        h2 = {"path": data.h2_path or "/"}
        if data.h2_host:
            h2["host"] = [data.h2_host]
        stream["httpSettings"] = h2

    # ── HTTPUpgrade ──
    elif data.network == "httpupgrade":
        hu = {"path": data.httpupgrade_path or "/"}
        if data.httpupgrade_host:
            hu["host"] = data.httpupgrade_host
        stream["httpupgradeSettings"] = hu

    # ── XHTTP (SplitHTTP) ──
    elif data.network == "xhttp":
        xh = {"path": data.xhttp_path or "/", "mode": data.xhttp_mode or "auto"}
        if data.xhttp_host:
            xh["host"] = data.xhttp_host
        stream["xhttpSettings"] = xh

    # ── TLS ──
    if data.security == "tls":
        tls = {
            "serverName": data.tls_server_name,
            "alpn": [a.strip() for a in data.tls_alpn.split(",") if a.strip()],
            "fingerprint": data.tls_fingerprint
        }
        if data.tls_cert_file and data.tls_key_file:
            tls["certificates"] = [{"certificateFile": data.tls_cert_file, "keyFile": data.tls_key_file}]
        stream["tlsSettings"] = tls

    # ── Reality ──
    elif data.security == "reality":
        priv = data.reality_private_key
        pub = data.reality_public_key
        if not priv or not pub:
            priv, pub = _generate_reality_keys()
        if not priv or not pub:
            logger.error("Reality keys empty! Xray binary may be missing or broken.")

        short_ids = [s.strip() for s in data.reality_short_ids.split(",") if s.strip()] if data.reality_short_ids else [secrets.token_hex(4)]
        server_names = [s.strip() for s in data.reality_server_names.split(",") if s.strip()]

        stream["realitySettings"] = {
            "show": False,
            "dest": data.reality_dest or "google.com:443",
            "xver": 0,
            "serverNames": server_names,
            "privateKey": priv,
            "shortIds": short_ids,
            "publicKey": pub,
            "fingerprint": data.reality_fingerprint or "chrome"
        }
        if data.reality_spider_x:
            stream["realitySettings"]["spiderX"] = data.reality_spider_x

    return stream


# ── API: Generate Reality Keys ──
@app.post("/api/generate-reality-keys")
async def api_gen_reality_keys(user: str = Depends(get_current_user)):
    if not XRAY_BIN.exists():
        raise HTTPException(400, "Install Xray first (Dashboard → Install Xray)")
    priv, pub = _generate_reality_keys()
    if not priv or not pub:
        raise HTTPException(400, "Key generation failed. Check xray binary.")
    return {"private_key": priv, "public_key": pub}


# ═══════════════════════════════════════════
#  API: CLIENTS
# ═══════════════════════════════════════════

class ClientCreate(BaseModel):
    email: str
    flow: str = ""
    expiry_days: int = 0
    traffic_limit_gb: float = 0
    ip_limit: int = 0


@app.post("/api/inbounds/{inbound_id}/clients")
async def api_add_client(inbound_id: int, data: ClientCreate, user: str = Depends(get_current_user)):
    conn = get_db()
    ib = conn.execute("SELECT * FROM inbounds WHERE id=?", (inbound_id,)).fetchone()
    if not ib:
        conn.close()
        raise HTTPException(404)
    client_uuid = str(uuid.uuid4())
    client_id = secrets.token_hex(8)
    expiry = 0
    if data.expiry_days > 0:
        expiry = int((datetime.now() + timedelta(days=data.expiry_days)).timestamp() * 1000)
    traffic = int(data.traffic_limit_gb * 1024 * 1024 * 1024)
    conn.execute(
        "INSERT INTO clients (id, inbound_id, email, uuid, flow, expiry_time, traffic_limit, ip_limit) VALUES (?,?,?,?,?,?,?,?)",
        (client_id, inbound_id, data.email, client_uuid, data.flow, expiry, traffic, data.ip_limit)
    )
    conn.commit()
    conn.close()
    restart_xray()
    return {"success": True, "id": client_id, "uuid": client_uuid}


class ClientUpdate(BaseModel):
    email: Optional[str] = None
    flow: Optional[str] = None
    enabled: Optional[bool] = None
    expiry_days: Optional[int] = None
    traffic_limit_gb: Optional[float] = None
    ip_limit: Optional[int] = None


@app.put("/api/clients/{client_id}")
async def api_update_client(client_id: str, data: ClientUpdate, user: str = Depends(get_current_user)):
    conn = get_db()
    row = conn.execute("SELECT * FROM clients WHERE id=?", (client_id,)).fetchone()
    if not row:
        conn.close()
        raise HTTPException(404)
    updates = []
    params = []
    if data.email is not None:
        updates.append("email=?"); params.append(data.email)
    if data.flow is not None:
        updates.append("flow=?"); params.append(data.flow)
    if data.enabled is not None:
        updates.append("enabled=?"); params.append(1 if data.enabled else 0)
    if data.expiry_days is not None:
        exp = int((datetime.now() + timedelta(days=data.expiry_days)).timestamp() * 1000) if data.expiry_days > 0 else 0
        updates.append("expiry_time=?"); params.append(exp)
    if data.traffic_limit_gb is not None:
        updates.append("traffic_limit=?"); params.append(int(data.traffic_limit_gb * 1024 * 1024 * 1024))
    if data.ip_limit is not None:
        updates.append("ip_limit=?"); params.append(data.ip_limit)
    if updates:
        params.append(client_id)
        conn.execute(f"UPDATE clients SET {', '.join(updates)} WHERE id=?", params)
        conn.commit()
    conn.close()
    restart_xray()
    return {"success": True}


@app.delete("/api/clients/{client_id}")
async def api_delete_client(client_id: str, user: str = Depends(get_current_user)):
    conn = get_db()
    conn.execute("DELETE FROM clients WHERE id=?", (client_id,))
    conn.commit()
    conn.close()
    restart_xray()
    return {"success": True}


@app.post("/api/clients/{client_id}/reset-traffic")
async def api_reset_client_traffic(client_id: str, user: str = Depends(get_current_user)):
    conn = get_db()
    conn.execute("UPDATE clients SET upload=0, download=0 WHERE id=?", (client_id,))
    conn.commit()
    conn.close()
    return {"success": True}


# ═══════════════════════════════════════════
#  API: LINKS
# ═══════════════════════════════════════════

@app.get("/api/clients/{client_id}/link")
async def api_client_link(client_id: str, request: Request, user: str = Depends(get_current_user)):
    conn = get_db()
    client = conn.execute("SELECT * FROM clients WHERE id=?", (client_id,)).fetchone()
    if not client:
        conn.close()
        raise HTTPException(404)
    ib = conn.execute("SELECT * FROM inbounds WHERE id=?", (client["inbound_id"],)).fetchone()
    conn.close()
    if not ib:
        raise HTTPException(404)
    host = request.headers.get("host", "").split(":")[0]
    if not host or host in ("0.0.0.0", "127.0.0.1"):
        host = "YOUR_SERVER_IP"
    stream = json.loads(ib["stream_settings"])
    settings = json.loads(ib["settings"])
    link = _generate_link(ib["protocol"], dict(client), dict(ib), stream, settings, host)
    return {"link": link, "protocol": ib["protocol"], "host": host, "port": ib["port"]}


def _generate_link(protocol, client, inbound, stream, settings, host):
    port = inbound["port"]
    uid = client["uuid"]
    ib_remark = inbound.get("remark", "")
    cl_name = client["email"]
    if ib_remark:
        remark = urllib.parse.quote(f"{ib_remark} | {cl_name}")
    else:
        remark = urllib.parse.quote(cl_name)
    network = stream.get("network", "tcp")
    security = stream.get("security", "none")

    if protocol == "vless":
        p = [f"type={network}", f"security={security}"]
        flow = client.get("flow", "")
        if flow:
            p.append(f"flow={flow}")
        if security == "reality":
            rs = stream.get("realitySettings", {})
            p.append(f"pbk={rs.get('publicKey', '')}")
            if rs.get("shortIds"): p.append(f"sid={rs['shortIds'][0]}")
            if rs.get("serverNames"): p.append(f"sni={rs['serverNames'][0]}")
            p.append(f"fp={rs.get('fingerprint', 'chrome')}")
            if rs.get("spiderX"): p.append(f"spx={urllib.parse.quote(rs['spiderX'])}")
        elif security == "tls":
            ts = stream.get("tlsSettings", {})
            if ts.get("serverName"): p.append(f"sni={ts['serverName']}")
            if ts.get("fingerprint"): p.append(f"fp={ts['fingerprint']}")
            if ts.get("alpn"): p.append(f"alpn={urllib.parse.quote(','.join(ts['alpn']))}")
        _add_transport_params(p, network, stream)
        return f"vless://{uid}@{host}:{port}?{'&'.join(p)}#{remark}"

    elif protocol == "vmess":
        obj = {
            "v": "2", "ps": client["email"], "add": host, "port": str(port),
            "id": uid, "aid": "0", "net": network, "type": "none",
            "host": "", "path": "", "tls": security if security != "none" else ""
        }
        if network == "ws":
            ws = stream.get("wsSettings", {})
            obj["path"] = ws.get("path", "/ws")
            obj["host"] = ws.get("headers", {}).get("Host", "")
        elif network == "grpc":
            obj["path"] = stream.get("grpcSettings", {}).get("serviceName", "")
            obj["type"] = "gun"
        elif network == "h2":
            h2 = stream.get("httpSettings", {})
            obj["path"] = h2.get("path", "/")
            obj["host"] = ",".join(h2.get("host", []))
        elif network == "tcp":
            tcp = stream.get("tcpSettings", {})
            if tcp.get("header", {}).get("type") == "http":
                obj["type"] = "http"
                req = tcp["header"].get("request", {})
                obj["path"] = ",".join(req.get("path", ["/"]))
                obj["host"] = ",".join(req.get("headers", {}).get("Host", []))
        if security == "tls":
            ts = stream.get("tlsSettings", {})
            obj["sni"] = ts.get("serverName", "")
            obj["fp"] = ts.get("fingerprint", "")
        return f"vmess://{base64.b64encode(json.dumps(obj).encode()).decode()}"

    elif protocol == "trojan":
        p = [f"type={network}", f"security={security}"]
        if security == "tls":
            ts = stream.get("tlsSettings", {})
            if ts.get("serverName"): p.append(f"sni={ts['serverName']}")
            if ts.get("fingerprint"): p.append(f"fp={ts['fingerprint']}")
            if ts.get("alpn"): p.append(f"alpn={urllib.parse.quote(','.join(ts['alpn']))}")
        elif security == "reality":
            rs = stream.get("realitySettings", {})
            p.append(f"pbk={rs.get('publicKey', '')}")
            if rs.get("shortIds"): p.append(f"sid={rs['shortIds'][0]}")
            if rs.get("serverNames"): p.append(f"sni={rs['serverNames'][0]}")
            p.append(f"fp={rs.get('fingerprint', 'chrome')}")
        _add_transport_params(p, network, stream)
        return f"trojan://{uid}@{host}:{port}?{'&'.join(p)}#{remark}"

    elif protocol == "shadowsocks":
        method = settings.get("method", "chacha20-ietf-poly1305")
        password = settings.get("password", uid)
        userinfo = base64.b64encode(f"{method}:{password}".encode()).decode()
        return f"ss://{userinfo}@{host}:{port}#{remark}"

    return ""


def _add_transport_params(params, network, stream):
    if network == "ws":
        ws = stream.get("wsSettings", {})
        if ws.get("path"): params.append(f"path={urllib.parse.quote(ws['path'])}")
        if ws.get("headers", {}).get("Host"): params.append(f"host={ws['headers']['Host']}")
    elif network == "grpc":
        gs = stream.get("grpcSettings", {})
        if gs.get("serviceName"): params.append(f"serviceName={gs['serviceName']}")
        if gs.get("multiMode"): params.append("mode=multi")
    elif network == "h2":
        h2 = stream.get("httpSettings", {})
        if h2.get("path"): params.append(f"path={urllib.parse.quote(h2['path'])}")
        if h2.get("host"): params.append(f"host={h2['host'][0]}")
    elif network == "httpupgrade":
        hu = stream.get("httpupgradeSettings", {})
        if hu.get("path"): params.append(f"path={urllib.parse.quote(hu['path'])}")
        if hu.get("host"): params.append(f"host={hu['host']}")
    elif network == "tcp":
        tcp = stream.get("tcpSettings", {})
        if tcp.get("header", {}).get("type") == "http":
            params.append("headerType=http")


# ═══════════════════════════════════════════
#  SUBSCRIPTION
# ═══════════════════════════════════════════

@app.get("/sub/{token}")
async def subscription(token: str, request: Request):
    conn = get_db()
    client = conn.execute("SELECT * FROM clients WHERE id=?", (token,)).fetchone()
    if not client:
        conn.close()
        raise HTTPException(404)
    all_clients = conn.execute(
        "SELECT c.*, i.protocol, i.port, i.listen, i.settings, i.stream_settings, i.remark, i.enabled "
        "FROM clients c JOIN inbounds i ON c.inbound_id=i.id "
        "WHERE c.email=? AND c.enabled=1 AND i.enabled=1",
        (client["email"],)
    ).fetchall()
    conn.close()

    host = request.headers.get("host", "").split(":")[0]
    if not host or host in ("0.0.0.0", "127.0.0.1", "localhost"):
        host = _get_server_ip(request)

    links = []
    for cl in all_clients:
        try:
            stream = json.loads(cl["stream_settings"])
            settings = json.loads(cl["settings"])
            ib_dict = {"port": cl["port"], "listen": cl["listen"], "remark": cl["remark"], "protocol": cl["protocol"]}
            cl_dict = {"uuid": cl["uuid"], "email": cl["email"], "flow": cl["flow"] or ""}
            link = _generate_link(cl["protocol"], cl_dict, ib_dict, stream, settings, host)
            if link:
                links.append(link)
        except:
            pass

    if not links:
        raise HTTPException(404, "No active links")

    all_links = "\n".join(links)

    ua = (request.headers.get("user-agent", "") or "").lower()
    is_app = any(x in ua for x in [
        "v2rayn", "hiddify", "nekobox", "nekoray", "clash", "surge", "shadowrocket",
        "streisand", "v2rayng", "sing-box", "stash", "quantumult", "happ", "v2box",
        "foxray", "loon", "karing", "surfboard", "mihomo",
    ]) or "mozilla" not in ua

    if is_app:
        sub_name = get_setting("sub_profile_title", "SelfRay-UI")
        total_up = sum(c["upload"] or 0 for c in all_clients)
        total_down = sum(c["download"] or 0 for c in all_clients)
        total_limit = max((c["traffic_limit"] or 0) for c in all_clients)
        headers = {
            "content-disposition": f'attachment; filename="{client["email"]}"',
            "profile-title": base64.b64encode(sub_name.encode()).decode(),
            "subscription-userinfo": f"upload={total_up}; download={total_down}; total={total_limit}",
            "profile-update-interval": "12",
        }
        return Response(content=base64.b64encode(all_links.encode()).decode(), media_type="text/plain", headers=headers)

    exp_str = "Unlimited"
    if client["expiry_time"] and client["expiry_time"] > 0:
        exp_dt = datetime.fromtimestamp(client["expiry_time"] / 1000)
        exp_str = exp_dt.strftime("%Y-%m-%d %H:%M")
    traf_str = "Unlimited"
    if client["traffic_limit"] and client["traffic_limit"] > 0:
        traf_str = f"{client['traffic_limit'] / (1024**3):.1f} GB"
    used = ((client["upload"] or 0) + (client["download"] or 0)) / (1024**3)

    return HTMLResponse(_sub_page_html(client["email"], links[0], client.get("protocol", "VLESS"), exp_str, traf_str, f"{used:.2f} GB", token, host, len(links)))


def _sub_page_html(name, link, proto, expiry, limit, used, token, host, total_links=1):
    panel_port = get_setting("panel_port", "8443")
    ssl_on = get_setting("ssl_enabled", "false") == "true"
    scheme = "https" if ssl_on else "http"
    sub_url = f"{scheme}://{host}:{panel_port}/sub/{token}"
    js_link = link.replace("\\", "\\\\").replace('"', '\\"').replace("'", "\\'")
    js_sub = sub_url.replace("\\", "\\\\").replace('"', '\\"').replace("'", "\\'")
    return f'''<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>SelfRay — {name}</title>
<script src="https://cdn.jsdelivr.net/npm/qrcodejs@1.0.0/qrcode.min.js"></script>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:'Segoe UI',system-ui,sans-serif;background:#08080d;color:#e0e0e0;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}}
body::before{{content:'';position:fixed;inset:0;background:radial-gradient(ellipse at 30% 0%,rgba(123,47,255,.08) 0%,transparent 60%),radial-gradient(ellipse at 70% 100%,rgba(0,200,255,.06) 0%,transparent 60%);pointer-events:none}}
.box{{background:rgba(16,16,26,.9);backdrop-filter:blur(20px);border:1px solid rgba(40,40,70,.5);border-radius:16px;padding:32px;max-width:440px;width:100%;animation:su .5s ease;position:relative;z-index:1}}
@keyframes su{{from{{opacity:0;transform:translateY(20px)}}to{{opacity:1;transform:translateY(0)}}}}
h1{{font-size:20px;background:linear-gradient(135deg,#00c8ff,#7b2fff);-webkit-background-clip:text;-webkit-text-fill-color:transparent;margin-bottom:4px}}
.sub{{color:#667;font-size:12px;margin-bottom:20px}}
.stats{{display:grid;grid-template-columns:1fr 1fr 1fr;gap:10px;margin-bottom:20px}}
.st{{background:rgba(8,8,15,.8);border:1px solid rgba(40,40,70,.4);border-radius:10px;padding:10px;text-align:center}}
.st .lb{{font-size:10px;color:#667;text-transform:uppercase;letter-spacing:.5px}}.st .vl{{font-size:14px;font-weight:600;margin-top:2px}}
.qr-wrap{{display:flex;justify-content:center;margin:16px 0;animation:su .7s ease}}
.qr-wrap canvas,.qr-wrap img{{border-radius:8px!important}}
.link-box{{background:rgba(8,8,15,.8);border:1px solid rgba(40,40,70,.4);border-radius:8px;padding:10px;word-break:break-all;font-family:monospace;font-size:10px;margin:12px 0;max-height:80px;overflow:auto;color:#888}}
.btn{{display:block;width:100%;padding:12px;border:none;border-radius:10px;font-size:13px;font-weight:600;cursor:pointer;transition:all .25s;margin-bottom:8px;text-align:center;text-decoration:none}}
.btn-p{{background:linear-gradient(135deg,#00c8ff,#7b2fff);color:#fff}}.btn-p:hover{{transform:translateY(-2px);box-shadow:0 4px 20px rgba(0,200,255,.3)}}
.btn-o{{background:transparent;border:1px solid rgba(40,40,70,.5);color:#e0e0e0}}.btn-o:hover{{border-color:#00c8ff;color:#00c8ff}}
.apps{{display:grid;grid-template-columns:1fr 1fr;gap:6px;margin-top:12px}}
.apps a{{font-size:11px;padding:8px;border-radius:8px;background:rgba(8,8,15,.6);border:1px solid rgba(40,40,70,.3);color:#aaa;text-align:center;text-decoration:none;transition:all .2s}}
.apps a:hover{{border-color:#00c8ff;color:#00c8ff;transform:translateY(-1px)}}
.toast{{position:fixed;bottom:20px;left:50%;transform:translateX(-50%) translateY(80px);background:linear-gradient(135deg,rgba(46,213,115,.9),rgba(46,213,115,.7));color:#000;padding:10px 24px;border-radius:10px;font-size:12px;font-weight:500;opacity:0;transition:all .3s;z-index:99}}
.toast.show{{transform:translateX(-50%) translateY(0);opacity:1}}
.footer{{text-align:center;margin-top:16px;font-size:10px;color:#445}}
</style></head><body>
<div class="box">
<h1>{name}</h1>
<div class="sub">{proto} subscription via SelfRay-UI</div>
<div class="stats">
<div class="st"><div class="lb">Expires</div><div class="vl" style="font-size:11px">{expiry}</div></div>
<div class="st"><div class="lb">Limit</div><div class="vl">{limit}</div></div>
<div class="st"><div class="lb">Used</div><div class="vl">{used}</div></div>
</div>
<div class="qr-wrap"><div id="qr"></div></div>
<div class="link-box" id="link">{link}</div>
<button class="btn btn-p" onclick="cp()">Copy Connection Link</button>
<button class="btn btn-o" onclick="cpSub()">Copy Subscription URL</button>
<div style="font-size:11px;color:#667;margin-top:14px;text-align:center">Open with</div>
<div class="apps">
<a href="v2rayn://install-sub?url={sub_url}&name={name}" target="_blank">v2rayN</a>
<a href="hiddify://install-config?url={sub_url}&name={name}" target="_blank">Hiddify</a>
<a href="clash://install-config?url={sub_url}" target="_blank">Clash / Streisand</a>
<a href="nekobox://subscribe?url={sub_url}&name={name}" target="_blank">NekoBox</a>
</div>
<div class="footer">Powered by SelfRay-UI</div>
</div>
<div class="toast" id="toast"></div>
<script>
new QRCode(document.getElementById("qr"),{{text:"{js_link}",width:180,height:180,colorDark:"#e0e0e0",colorLight:"#10101a",correctLevel:QRCode.CorrectLevel.M}});
function cp(){{navigator.clipboard.writeText("{js_link}");notify("Link copied!")}}
function cpSub(){{navigator.clipboard.writeText("{js_sub}");notify("Subscription URL copied!")}}
function notify(m){{const t=document.getElementById("toast");t.textContent=m;t.classList.add("show");setTimeout(()=>t.classList.remove("show"),2000)}}
</script></body></html>'''


# ═══════════════════════════════════════════
#  API: BACKUP / EXPORT
# ═══════════════════════════════════════════

@app.get("/api/backup")
async def api_backup(user: str = Depends(get_current_user)):
    if DB_PATH.exists():
        data = base64.b64encode(DB_PATH.read_bytes()).decode()
        return {"database": data, "timestamp": datetime.now().isoformat()}
    return {"error": "No database"}


WHITELIST_URL = "https://raw.githubusercontent.com/hxehex/russia-mobile-internet-whitelist/main/whitelist.txt"


@app.get("/api/whitelist")
async def api_get_whitelist(user: str = Depends(get_current_user)):
    wl_path = APP_DIR / "static" / "whitelist-ru.txt"
    if wl_path.exists():
        domains = [d.strip() for d in wl_path.read_text().splitlines() if d.strip() and not d.startswith("#")]
        return {"domains": domains, "count": len(domains)}
    return {"domains": [], "count": 0}


@app.post("/api/whitelist/update")
async def api_update_whitelist(user: str = Depends(get_current_user)):
    wl_path = APP_DIR / "static" / "whitelist-ru.txt"
    try:
        import urllib.request
        req = urllib.request.Request(WHITELIST_URL, headers={"User-Agent": "SelfRay-UI"})
        resp = urllib.request.urlopen(req, timeout=30)
        data = resp.read().decode("utf-8", errors="ignore")
        lines = [l.strip() for l in data.splitlines() if l.strip() and not l.startswith("#")]
        if len(lines) < 5:
            return {"success": False, "error": "Downloaded file too small, possibly invalid"}
        wl_path.write_text("\n".join(lines) + "\n")
        return {"success": True, "count": len(lines)}
    except Exception as e:
        return {"success": False, "error": str(e)}


@app.post("/api/apply-whitelist")
async def api_apply_whitelist(user: str = Depends(get_current_user)):
    wl_path = APP_DIR / "static" / "whitelist-ru.txt"
    if not wl_path.exists():
        raise HTTPException(400, "Whitelist file not found")
    domains = [d.strip() for d in wl_path.read_text().splitlines() if d.strip()]
    rule = json.dumps([{
        "type": "field",
        "domain": [f"full:{d}" for d in domains],
        "outboundTag": "direct"
    }])
    set_setting("custom_routing_rules", rule)
    restart_xray()
    return {"success": True, "count": len(domains)}


# ═══════════════════════════════════════════
#  API: TELEGRAM
# ═══════════════════════════════════════════

def _tg_send(text, token_override="", chat_id_override=""):
    token = token_override or get_setting("tg_bot_token", "")
    chat_id = chat_id_override or get_setting("tg_chat_id", "")
    if not token or not chat_id:
        return False, "Bot token or chat ID is empty"
    try:
        import urllib.request, urllib.error
        url = f"https://api.telegram.org/bot{token}/sendMessage"
        payload = json.dumps({"chat_id": chat_id, "text": text, "parse_mode": "HTML"}).encode()
        req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"})
        resp = urllib.request.urlopen(req, timeout=10)
        body = json.loads(resp.read().decode())
        if body.get("ok"):
            return True, ""
        return False, body.get("description", "Unknown Telegram error")
    except urllib.error.HTTPError as e:
        try:
            err_body = json.loads(e.read().decode())
            return False, err_body.get("description", f"HTTP {e.code}")
        except:
            return False, f"HTTP {e.code}"
    except Exception as e:
        logger.error(f"Telegram send error: {e}")
        return False, str(e)


@app.post("/api/telegram/test")
async def api_tg_test(request: Request, user: str = Depends(get_current_user)):
    body = await request.json() if request.headers.get("content-type", "").startswith("application/json") else {}
    token = body.get("token", "") or get_setting("tg_bot_token", "")
    chat_id = body.get("chat_id", "") or get_setting("tg_chat_id", "")
    if not token or not chat_id:
        return {"success": False, "error": "Bot token and chat ID are required. Fill them and Save first."}
    ok, err = _tg_send("✅ <b>SelfRay-UI</b>\nTest message — bot is working!", token, chat_id)
    if ok:
        return {"success": True}
    return {"success": False, "error": err or "Failed"}


@app.post("/api/telegram/reset")
async def api_tg_reset(user: str = Depends(get_current_user)):
    for k in ("tg_bot_token", "tg_chat_id"):
        set_setting(k, "")
    return {"success": True}


# ═══════════════════════════════════════════
#  API: TOTP (2FA)
# ═══════════════════════════════════════════

@app.get("/api/totp/status")
async def api_totp_status(user: str = Depends(get_current_user)):
    return {"enabled": get_setting("totp_enabled", "false") == "true"}


@app.post("/api/totp/setup")
async def api_totp_setup(user: str = Depends(get_current_user)):
    try:
        import pyotp
    except ImportError:
        raise HTTPException(400, "pyotp not installed. Run: pip install pyotp")
    secret = pyotp.random_base32()
    set_setting("totp_secret_pending", secret)
    totp = pyotp.TOTP(secret)
    qr_url = totp.provisioning_uri(name="admin", issuer_name="SelfRay-UI")
    return {"secret": secret, "qr_url": qr_url}


class TotpVerify(BaseModel):
    code: str


@app.post("/api/totp/verify")
async def api_totp_verify(data: TotpVerify, user: str = Depends(get_current_user)):
    try:
        import pyotp
    except ImportError:
        raise HTTPException(400, "pyotp not installed")
    secret = get_setting("totp_secret_pending", "")
    if not secret:
        raise HTTPException(400, "No pending 2FA setup")
    totp = pyotp.TOTP(secret)
    if totp.verify(data.code):
        set_setting("totp_secret", secret)
        set_setting("totp_enabled", "true")
        set_setting("totp_secret_pending", "")
        return {"success": True}
    return {"success": False, "error": "Invalid code"}


@app.post("/api/totp/disable")
async def api_totp_disable(user: str = Depends(get_current_user)):
    set_setting("totp_enabled", "false")
    set_setting("totp_secret", "")
    return {"success": True}


# ═══════════════════════════════════════════
#  API: WARP
# ═══════════════════════════════════════════

WARP_CONF = Path("/etc/selfray/warp.conf")
WARP_SOCKS_PORT = 40000


class WarpSave(BaseModel):
    mode: str = "off"
    license_key: str = ""
    domains: str = ""


@app.post("/api/warp/save")
async def api_warp_save(data: WarpSave, user: str = Depends(get_current_user)):
    set_setting("warp_mode", data.mode)
    set_setting("warp_license_key", data.license_key)
    set_setting("warp_domains", data.domains)
    _apply_warp_routing(data.mode, data.domains)
    return {"success": True}


@app.post("/api/warp/install")
async def api_warp_install(user: str = Depends(get_current_user)):
    try:
        script = """
set -e
if command -v warp-cli >/dev/null 2>&1; then echo "already_installed"; exit 0; fi
curl -fsSL https://pkg.cloudflareclient.com/pubkey.gpg | gpg --yes --dearmor -o /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg 2>/dev/null
CODENAME=$(lsb_release -cs 2>/dev/null || echo "focal")
echo "deb [signed-by=/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg] https://pkg.cloudflareclient.com/ $CODENAME main" > /etc/apt/sources.list.d/cloudflare-client.list
apt-get update -qq && apt-get install -y -qq cloudflare-warp >/dev/null 2>&1
echo "installed"
"""
        r = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=180)
        if r.returncode != 0:
            return {"success": False, "error": r.stderr[-500:] if r.stderr else "Install failed"}
        reg = subprocess.run(["bash", "-c", """
if ! warp-cli --accept-tos registration show >/dev/null 2>&1; then
    warp-cli --accept-tos registration new 2>/dev/null || true
fi
warp-cli --accept-tos mode proxy 2>/dev/null || true
warp-cli --accept-tos proxy port 40000 2>/dev/null || true
sleep 1
warp-cli --accept-tos connect 2>/dev/null || true
sleep 2
echo "ok"
"""], capture_output=True, text=True, timeout=30)
        license_key = get_setting("warp_license_key", "")
        if license_key:
            subprocess.run(["warp-cli", "--accept-tos", "registration", "license", license_key],
                           capture_output=True, text=True, timeout=15)
        return {"success": True}
    except Exception as e:
        return {"success": False, "error": str(e)}


@app.post("/api/warp/test")
async def api_warp_test(user: str = Depends(get_current_user)):
    try:
        r = subprocess.run(
            ["curl", "-s", "--max-time", "10", "--socks5", f"127.0.0.1:{WARP_SOCKS_PORT}", "https://ifconfig.me"],
            capture_output=True, text=True, timeout=15
        )
        if r.returncode == 0 and r.stdout.strip():
            return {"success": True, "ip": r.stdout.strip()}
        return {"success": False, "error": "WARP not connected. Run Install first."}
    except Exception as e:
        return {"success": False, "error": str(e)}


@app.get("/api/warp/status")
async def api_warp_status(user: str = Depends(get_current_user)):
    installed = False
    connected = False
    mode = "unknown"
    account = ""
    try:
        r = subprocess.run(["which", "warp-cli"], capture_output=True, text=True, timeout=5)
        installed = r.returncode == 0
    except:
        pass
    if installed:
        try:
            r = subprocess.run(["warp-cli", "--accept-tos", "status"], capture_output=True, text=True, timeout=5)
            out = r.stdout.lower()
            connected = "connected" in out and "disconnected" not in out
            if "warp+" in out:
                account = "WARP+"
            elif "warp" in out:
                account = "WARP Free"
        except:
            pass
        try:
            r = subprocess.run(["warp-cli", "--accept-tos", "settings"], capture_output=True, text=True, timeout=5)
            if "proxy" in r.stdout.lower():
                mode = "proxy"
        except:
            pass
    return {
        "installed": installed,
        "connected": connected,
        "mode": mode,
        "account": account,
        "socks_port": WARP_SOCKS_PORT
    }


def _apply_warp_routing(mode, domains_str=""):
    if mode == "off":
        _remove_warp_outbound()
        return
    outbounds = _get_xray_outbounds()
    outbounds = [o for o in outbounds if o.get("tag") not in ("warp", "warp-socks5")]
    outbounds.append({
        "tag": "warp-socks5",
        "protocol": "socks",
        "settings": {
            "servers": [{"address": "127.0.0.1", "port": WARP_SOCKS_PORT}]
        }
    })
    outbounds.append({
        "tag": "warp",
        "protocol": "freedom",
        "proxySettings": {"tag": "warp-socks5"},
        "settings": {"domainStrategy": "UseIPv4"}
    })
    _set_xray_outbounds(outbounds)
    rules = json.loads(get_setting("custom_routing_rules", "[]") or "[]")
    rules = [r for r in rules if r.get("outboundTag") not in ("warp", "warp-socks5")]
    if mode == "all":
        rules.insert(0, {
            "type": "field",
            "outboundTag": "warp",
            "network": "tcp,udp"
        })
    elif mode == "geo":
        domains = [d.strip() for d in domains_str.split(",") if d.strip()]
        if domains:
            domain_rules = []
            for d in domains:
                if d.startswith("geosite:") or d.startswith("regexp:") or d.startswith("domain:"):
                    domain_rules.append(d)
                else:
                    domain_rules.append(f"domain:{d}")
            rules.insert(0, {
                "type": "field",
                "domain": domain_rules,
                "outboundTag": "warp"
            })
    set_setting("custom_routing_rules", json.dumps(rules))
    restart_xray()


def _remove_warp_outbound():
    outbounds = _get_xray_outbounds()
    outbounds = [o for o in outbounds if o.get("tag") not in ("warp", "warp-socks5")]
    _set_xray_outbounds(outbounds)
    rules = json.loads(get_setting("custom_routing_rules", "[]") or "[]")
    rules = [r for r in rules if r.get("outboundTag") not in ("warp", "warp-socks5")]
    set_setting("custom_routing_rules", json.dumps(rules))
    restart_xray()


def _get_xray_outbounds():
    try:
        if XRAY_CONFIG_PATH.exists():
            conf = json.loads(XRAY_CONFIG_PATH.read_text())
            return conf.get("outbounds", [])
    except:
        pass
    return [{"tag": "direct", "protocol": "freedom"}, {"tag": "blocked", "protocol": "blackhole"}]


def _set_xray_outbounds(outbounds):
    set_setting("custom_outbounds", json.dumps(outbounds))


_bot_instance = None

def _start_tg_bot():
    global _bot_instance
    from app.tg_bot import SelfRayBot
    _bot_instance = SelfRayBot(
        get_setting_fn=get_setting,
        set_setting_fn=set_setting,
        hash_password_fn=hash_password,
        get_db_fn=get_db,
    )
    _bot_instance.start()


@app.on_event("startup")
async def on_startup():
    try:
        token = get_setting("tg_bot_token", "")
        chat_id = get_setting("tg_chat_id", "")
        if token and chat_id:
            _start_tg_bot()
    except Exception as e:
        logger.error(f"Bot start error: {e}")


@app.post("/api/telegram/restart-bot")
async def api_tg_restart_bot(user: str = Depends(get_current_user)):
    global _bot_instance
    try:
        if _bot_instance:
            _bot_instance.stop()
        _start_tg_bot()
        return {"success": True}
    except Exception as e:
        return {"success": False, "error": str(e)}


if __name__ == "__main__":
    import uvicorn
    setup_admin()
    port = int(get_setting("panel_port", "8443"))
    host = get_setting("panel_host", "0.0.0.0")
    if len(sys.argv) > 1: port = int(sys.argv[1])
    if len(sys.argv) > 2: host = sys.argv[2]
    kw = {}
    ssl_on = get_setting("ssl_enabled", "false") == "true"
    cert = get_setting("ssl_cert_path", "")
    key = get_setting("ssl_key_path", "")
    if ssl_on and cert and key and Path(cert).exists() and Path(key).exists():
        kw["ssl_certfile"] = cert
        kw["ssl_keyfile"] = key
        logger.info(f"HTTPS enabled: {cert}")
    uvicorn.run(app, host=host, port=port, **kw)
