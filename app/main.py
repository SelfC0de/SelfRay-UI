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
        "api": {"tag": "api", "services": ["StatsService"]},
        "stats": {},
        "policy": {
            "system": {"statsInboundUplink": True, "statsInboundDownlink": True}
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
        lines = result.stdout.strip().split("\n")
        priv = pub = ""
        for line in lines:
            if "Private" in line:
                priv = line.split(":")[-1].strip()
            elif "Public" in line:
                pub = line.split(":")[-1].strip()
        return priv, pub
    except:
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
    yield
    stop_xray()


app = FastAPI(title="SelfRay-UI", lifespan=lifespan)
app.add_middleware(SessionMiddleware, secret_key=secrets.token_hex(32))
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

@app.get("/", response_class=HTMLResponse)
async def root(request: Request):
    if request.session.get("user"):
        return RedirectResponse("/panel", status_code=302)
    return RedirectResponse("/login", status_code=302)


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})


@app.post("/login")
async def login(request: Request, username: str = Form(...), password: str = Form(...)):
    conn = get_db()
    user = conn.execute(
        "SELECT * FROM users WHERE username=? AND password_hash=?",
        (username, hash_password(password))
    ).fetchone()
    conn.close()
    if not user:
        return templates.TemplateResponse("login.html", {"request": request, "error": "Wrong login or password"})
    request.session["user"] = username
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
async def api_status(user: str = Depends(get_current_user)):
    uptime = 0
    try:
        with open("/proc/uptime") as f:
            uptime = int(float(f.read().split()[0]))
    except:
        pass
    return {
        "xray_running": is_xray_running(),
        "xray_installed": XRAY_BIN.exists(),
        "pid": xray_process.pid if is_xray_running() else None,
        "uptime": uptime
    }


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
        return {"installed": True, "version": r.stdout.split("\n")[0]}
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
#  API: INBOUNDS (full settings like 3x-ui)
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
    tls_allow_insecure: bool = False
    # Reality
    reality_dest: str = "google.com:443"
    reality_server_names: str = "google.com"
    reality_private_key: str = ""
    reality_public_key: str = ""
    reality_short_ids: str = ""
    reality_spider_x: str = ""
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
    # Sniffing
    sniffing_enabled: bool = True
    sniffing_dest_override: str = "http,tls,quic"
    sniffing_route_only: bool = False


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


@app.post("/api/inbounds")
async def api_create_inbound(data: InboundCreate, user: str = Depends(get_current_user)):
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
    try:
        conn.execute(
            "INSERT INTO inbounds (tag, protocol, listen, port, settings, stream_settings, sniffing, remark) VALUES (?,?,?,?,?,?,?,?)",
            (tag, data.protocol, data.listen, data.port, json.dumps(settings), json.dumps(stream), json.dumps(sniffing), data.remark)
        )
        conn.commit()
        inbound_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    except sqlite3.IntegrityError:
        conn.close()
        raise HTTPException(400, f"Tag conflict: {tag}")

    if data.protocol != "shadowsocks":
        client_uuid = str(uuid.uuid4())
        client_id = secrets.token_hex(8)
        conn.execute(
            "INSERT INTO clients (id, inbound_id, email, uuid, flow) VALUES (?,?,?,?,?)",
            (client_id, inbound_id, "default-user", client_uuid, data.flow if data.protocol == "vless" else "")
        )
        conn.commit()

    conn.close()
    restart_xray()
    return {"success": True, "id": inbound_id}


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

    # ── TLS ──
    if data.security == "tls":
        tls = {
            "serverName": data.tls_server_name,
            "alpn": [a.strip() for a in data.tls_alpn.split(",") if a.strip()],
            "fingerprint": data.tls_fingerprint,
            "allowInsecure": data.tls_allow_insecure
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

        short_ids = [s.strip() for s in data.reality_short_ids.split(",") if s.strip()] if data.reality_short_ids else [secrets.token_hex(4)]
        server_names = [s.strip() for s in data.reality_server_names.split(",") if s.strip()]

        stream["realitySettings"] = {
            "show": False,
            "dest": data.reality_dest or "google.com:443",
            "xver": 0,
            "serverNames": server_names,
            "privateKey": priv,
            "shortIds": short_ids,
            "publicKey": pub
        }
        if data.reality_spider_x:
            stream["realitySettings"]["spiderX"] = data.reality_spider_x

    return stream


# ── API: Generate Reality Keys ──
@app.post("/api/generate-reality-keys")
async def api_gen_reality_keys(user: str = Depends(get_current_user)):
    priv, pub = _generate_reality_keys()
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
    remark = urllib.parse.quote(client["email"])
    network = stream.get("network", "tcp")
    security = stream.get("security", "none")

    if protocol == "vless":
        p = [f"type={network}", f"security={security}"]
        flow = client.get("flow", "")
        if flow:
            p.append(f"flow={flow}")
        if security == "reality":
            rs = stream.get("realitySettings", {})
            if rs.get("publicKey"): p.append(f"pbk={rs['publicKey']}")
            if rs.get("shortIds"): p.append(f"sid={rs['shortIds'][0]}")
            if rs.get("serverNames"): p.append(f"sni={rs['serverNames'][0]}")
            p.append(f"fp=chrome")
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
            if rs.get("publicKey"): p.append(f"pbk={rs['publicKey']}")
            if rs.get("shortIds"): p.append(f"sid={rs['shortIds'][0]}")
            if rs.get("serverNames"): p.append(f"sni={rs['serverNames'][0]}")
            p.append("fp=chrome")
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
    ib = conn.execute("SELECT * FROM inbounds WHERE id=?", (client["inbound_id"],)).fetchone()
    conn.close()
    if not ib:
        raise HTTPException(404)
    host = request.headers.get("host", "").split(":")[0]
    stream = json.loads(ib["stream_settings"])
    settings = json.loads(ib["settings"])
    link = _generate_link(ib["protocol"], dict(client), dict(ib), stream, settings, host)
    return Response(content=base64.b64encode(link.encode()).decode(), media_type="text/plain")


# ═══════════════════════════════════════════
#  API: BACKUP / EXPORT
# ═══════════════════════════════════════════

@app.get("/api/backup")
async def api_backup(user: str = Depends(get_current_user)):
    if DB_PATH.exists():
        data = base64.b64encode(DB_PATH.read_bytes()).decode()
        return {"database": data, "timestamp": datetime.now().isoformat()}
    return {"error": "No database"}


if __name__ == "__main__":
    import uvicorn
    init_db()
    setup_admin()
    port = int(get_setting("panel_port", "8443"))
    host = get_setting("panel_host", "0.0.0.0")
    if len(sys.argv) > 1: port = int(sys.argv[1])
    if len(sys.argv) > 2: host = sys.argv[2]
    uvicorn.run(app, host=host, port=port)
