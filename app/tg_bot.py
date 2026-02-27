import json
import time
import threading
import logging
import urllib.request
import urllib.error
import urllib.parse

logger = logging.getLogger("tg_bot")

PRESETS = {
    "speed": {"protocol": "vless", "network": "tcp", "security": "reality", "flow": "xtls-rprx-vision", "port": 443, "label": "⚡ Max Speed (VLESS+TCP+Reality)"},
    "stealth": {"protocol": "vless", "network": "xhttp", "security": "reality", "flow": "", "port": 443, "label": "🛡️ Max Stealth (VLESS+XHTTP+Reality)"},
    "streaming": {"protocol": "vless", "network": "ws", "security": "tls", "flow": "", "port": 443, "label": "📺 Streaming (VLESS+WS+TLS)"},
    "gaming": {"protocol": "vless", "network": "grpc", "security": "reality", "flow": "", "port": 443, "label": "🎮 Gaming (VLESS+gRPC+Reality)"},
}

DEST_OPTIONS = [
    {"text": "google.com:443", "data": "dest_google.com:443"},
    {"text": "microsoft.com:443", "data": "dest_microsoft.com:443"},
    {"text": "apple.com:443", "data": "dest_apple.com:443"},
    {"text": "yahoo.com:443", "data": "dest_yahoo.com:443"},
    {"text": "cloudflare.com:443", "data": "dest_cloudflare.com:443"},
    {"text": "✏️ Custom", "data": "dest_custom"},
]

FP_OPTIONS = [
    {"text": "chrome", "data": "fp_chrome"},
    {"text": "firefox", "data": "fp_firefox"},
    {"text": "safari", "data": "fp_safari"},
    {"text": "edge", "data": "fp_edge"},
    {"text": "random", "data": "fp_random"},
    {"text": "randomized", "data": "fp_randomized"},
]


class SelfRayBot:
    def __init__(self, get_setting_fn, set_setting_fn, create_inbound_fn, hash_password_fn, get_db_fn, restart_panel_fn=None):
        self.get_setting = get_setting_fn
        self.set_setting = set_setting_fn
        self.create_inbound = create_inbound_fn
        self.hash_password = hash_password_fn
        self.get_db = get_db_fn
        self.restart_panel = restart_panel_fn
        self._offset = 0
        self._running = False
        self._thread = None
        self._user_states = {}

    @property
    def token(self):
        return self.get_setting("tg_bot_token", "")

    @property
    def chat_id(self):
        return self.get_setting("tg_chat_id", "")

    def _api(self, method, data=None):
        if not self.token:
            return None
        url = f"https://api.telegram.org/bot{self.token}/{method}"
        try:
            if data:
                payload = json.dumps(data).encode()
                req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"})
            else:
                req = urllib.request.Request(url)
            resp = urllib.request.urlopen(req, timeout=30)
            return json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            try:
                return json.loads(e.read().decode())
            except:
                return None
        except Exception as e:
            logger.error(f"TG API error: {e}")
            return None

    def send(self, text, chat_id=None, reply_markup=None):
        data = {"chat_id": chat_id or self.chat_id, "text": text, "parse_mode": "HTML"}
        if reply_markup:
            data["reply_markup"] = reply_markup
        return self._api("sendMessage", data)

    def answer_callback(self, callback_id, text=""):
        return self._api("answerCallbackQuery", {"callback_query_id": callback_id, "text": text})

    def _is_admin(self, chat_id):
        return str(chat_id) == str(self.chat_id)

    def start(self):
        if self._running:
            return
        if not self.token or not self.chat_id:
            return
        self._running = True
        self._thread = threading.Thread(target=self._poll_loop, daemon=True)
        self._thread.start()
        logger.info("Telegram bot started")

    def stop(self):
        self._running = False

    def _poll_loop(self):
        while self._running:
            if not self.token:
                time.sleep(5)
                continue
            try:
                result = self._api("getUpdates", {"offset": self._offset, "timeout": 20})
                if not result or not result.get("ok"):
                    time.sleep(5)
                    continue
                for update in result.get("result", []):
                    self._offset = update["update_id"] + 1
                    self._handle_update(update)
            except Exception as e:
                logger.error(f"Poll error: {e}")
                time.sleep(5)

    def _handle_update(self, update):
        if "callback_query" in update:
            self._handle_callback(update["callback_query"])
            return
        msg = update.get("message")
        if not msg or not msg.get("text"):
            return
        chat_id = msg["chat"]["id"]
        if not self._is_admin(chat_id):
            self.send("⛔ Access denied.", chat_id)
            return
        text = msg["text"].strip()
        state = self._user_states.get(chat_id)

        if text == "/start" or text == "/menu":
            self._user_states.pop(chat_id, None)
            self._send_menu(chat_id)
        elif text == "/cancel":
            self._user_states.pop(chat_id, None)
            self.send("❌ Cancelled.", chat_id)
            self._send_menu(chat_id)
        elif text == "/status":
            self._cmd_status(chat_id)
        elif text == "/list":
            self._cmd_list(chat_id)
        elif text == "/help":
            self._cmd_help(chat_id)
        elif state:
            self._handle_state(chat_id, text, state)
        else:
            self._send_menu(chat_id)

    def _send_menu(self, chat_id):
        kb = {"inline_keyboard": [
            [{"text": "📊 Status", "callback_data": "status"}, {"text": "📋 Inbounds", "callback_data": "list"}],
            [{"text": "➕ Create Inbound", "callback_data": "create_ib"}],
            [{"text": "🔑 Change Password", "callback_data": "chpass"}, {"text": "🔧 Change Port", "callback_data": "chport"}],
        ]}
        self.send("🏠 <b>SelfRay-UI</b> — Main Menu\n\nChoose an action:", chat_id, reply_markup=kb)

    def _handle_callback(self, cb):
        chat_id = cb["message"]["chat"]["id"]
        if not self._is_admin(chat_id):
            self.answer_callback(cb["id"], "Access denied")
            return
        data = cb.get("data", "")
        self.answer_callback(cb["id"])

        if data == "status":
            self._cmd_status(chat_id)
        elif data == "list":
            self._cmd_list(chat_id)
        elif data == "create_ib":
            self._cmd_create_start(chat_id)
        elif data.startswith("preset_"):
            self._cmd_create_preset(chat_id, data.replace("preset_", ""))
        elif data.startswith("dest_"):
            self._cb_dest(chat_id, data.replace("dest_", ""))
        elif data.startswith("fp_"):
            self._cb_fingerprint(chat_id, data.replace("fp_", ""))
        elif data == "chpass":
            self._cmd_chpass_start(chat_id)
        elif data == "chport":
            self._cmd_chport_start(chat_id)
        elif data == "menu":
            self._user_states.pop(chat_id, None)
            self._send_menu(chat_id)

    def _handle_state(self, chat_id, text, state):
        action = state.get("action")

        if action == "create_ib_port":
            try:
                port = int(text)
                if port < 1 or port > 65535:
                    raise ValueError
            except:
                self.send("❌ Invalid port. Enter 1-65535:", chat_id)
                return
            state["port"] = port
            preset = state.get("preset", "speed")
            p = PRESETS[preset]
            if p["security"] == "reality":
                state["action"] = "create_ib_dest"
                kb = {"inline_keyboard": [[o] for o in DEST_OPTIONS]}
                self.send(
                    "🎯 <b>Reality Dest (target server)</b>\n\n"
                    "This is the real website your server will impersonate.\n"
                    "DPI will see traffic to this site, not to your proxy.\n\n"
                    "Choose one or enter custom:",
                    chat_id, reply_markup=kb
                )
            elif p["security"] == "tls":
                state["action"] = "create_ib_tls_sni"
                self.send("🌐 <b>TLS Server Name (SNI)</b>\n\nEnter your domain (e.g. <code>example.com</code>):", chat_id)
            else:
                state["action"] = "create_ib_remark"
                self.send("📝 Enter remark (name):", chat_id)

        elif action == "create_ib_dest_custom":
            dest = text.strip()
            if ":" not in dest:
                dest += ":443"
            state["dest"] = dest
            sni = dest.split(":")[0]
            state["sni"] = sni
            self._ask_sni(chat_id, state, sni)

        elif action == "create_ib_sni":
            if text != "-":
                state["sni"] = text.strip()
            self._ask_fingerprint(chat_id, state)

        elif action == "create_ib_tls_sni":
            state["tls_sni"] = text.strip()
            state["action"] = "create_ib_remark"
            self.send("📝 Enter remark (name):", chat_id)

        elif action == "create_ib_remark":
            state["remark"] = text
            state["action"] = "create_ib_client"
            self.send("👤 Enter first client name (or <code>-</code> for default):", chat_id)

        elif action == "create_ib_client":
            client_name = "" if text == "-" else text
            self._do_create_inbound(chat_id, state, client_name)

        elif action == "chpass_old":
            conn = self.get_db()
            user = conn.execute("SELECT * FROM users WHERE password_hash=?", (self.hash_password(text),)).fetchone()
            conn.close()
            if not user:
                self.send("❌ Wrong current password. Try again:", chat_id)
                return
            state["username"] = user["username"]
            state["action"] = "chpass_new"
            self.send("🔐 Enter new password:", chat_id)

        elif action == "chpass_new":
            if len(text) < 4:
                self.send("❌ Too short. Minimum 4 characters:", chat_id)
                return
            conn = self.get_db()
            conn.execute("UPDATE users SET password_hash=? WHERE username=?",
                         (self.hash_password(text), state["username"]))
            conn.commit()
            conn.close()
            self.send("✅ Password changed!", chat_id)
            self._user_states.pop(chat_id, None)
            self._send_menu(chat_id)

        elif action == "chport":
            try:
                port = int(text)
                if port < 1 or port > 65535:
                    raise ValueError
            except:
                self.send("❌ Invalid port. Enter 1-65535:", chat_id)
                return
            self.set_setting("panel_port", str(port))
            self.send(f"✅ Panel port → <b>{port}</b>\n\n⚠️ Run <code>selfray restart</code> to apply.", chat_id)
            self._user_states.pop(chat_id, None)
            self._send_menu(chat_id)

    def _cb_dest(self, chat_id, value):
        state = self._user_states.get(chat_id)
        if not state or not state.get("action", "").startswith("create_ib_dest"):
            return
        if value == "custom":
            state["action"] = "create_ib_dest_custom"
            self.send("✏️ Enter dest (e.g. <code>example.com:443</code>):", chat_id)
            return
        state["dest"] = value
        sni = value.split(":")[0]
        state["sni"] = sni
        self._ask_sni(chat_id, state, sni)

    def _ask_sni(self, chat_id, state, default_sni):
        state["action"] = "create_ib_sni"
        self.send(
            f"🌐 <b>Server Names (SNI)</b>\n\n"
            f"Must match the Dest domain for Reality to work.\n"
            f"Default: <code>{default_sni}</code>\n\n"
            f"Send <code>-</code> to use default, or enter custom SNI:",
            chat_id
        )

    def _ask_fingerprint(self, chat_id, state):
        state["action"] = "create_ib_fp"
        kb = {"inline_keyboard": [
            [FP_OPTIONS[i], FP_OPTIONS[i+1]] for i in range(0, len(FP_OPTIONS)-1, 2)
        ]}
        self.send(
            "🖐 <b>uTLS Fingerprint</b>\n\n"
            "Simulates TLS handshake of a real browser.\n"
            "<code>chrome</code> — safest default\n"
            "<code>random</code> — different each time",
            chat_id, reply_markup=kb
        )

    def _cb_fingerprint(self, chat_id, value):
        state = self._user_states.get(chat_id)
        if not state or state.get("action") != "create_ib_fp":
            return
        state["fingerprint"] = value
        state["action"] = "create_ib_remark"
        self.send("📝 Enter remark (name):", chat_id)

    def _do_create_inbound(self, chat_id, state, client_name):
        preset = state.get("preset", "speed")
        p = PRESETS[preset]
        kwargs = {
            "protocol": p["protocol"],
            "port": state["port"],
            "remark": state.get("remark", ""),
            "network": p["network"],
            "security": p["security"],
            "flow": p["flow"],
            "client_name": client_name,
        }
        if p["security"] == "reality":
            kwargs["reality_dest"] = state.get("dest", "google.com:443")
            kwargs["reality_server_names"] = state.get("sni", "google.com")
            kwargs["reality_fingerprint"] = state.get("fingerprint", "chrome")
        elif p["security"] == "tls":
            kwargs["tls_server_name"] = state.get("tls_sni", "")

        self.send("⏳ Creating inbound...", chat_id)
        try:
            result = self.create_inbound(**kwargs)
            if result.get("success"):
                ib_id = result.get("id", "?")
                link = result.get("link", "")
                msg = f"✅ <b>Inbound created!</b>\n\n"
                msg += f"ID: <code>{ib_id}</code>\n"
                msg += f"Preset: {p['label']}\n"
                msg += f"Port: {state['port']}\n"
                if state.get("remark"):
                    msg += f"Remark: {state['remark']}\n"
                if p["security"] == "reality":
                    msg += f"Dest: <code>{state.get('dest', '-')}</code>\n"
                    msg += f"SNI: <code>{state.get('sni', '-')}</code>\n"
                    msg += f"Fingerprint: <code>{state.get('fingerprint', 'chrome')}</code>\n"
                    msg += f"Keys: ✅ auto-generated\n"
                if link:
                    msg += f"\n🔗 <b>Connection link:</b>\n<code>{link}</code>"
                self.send(msg, chat_id)
            else:
                self.send(f"❌ Error: {result.get('error', 'Unknown')}", chat_id)
        except Exception as e:
            self.send(f"❌ Error: {e}", chat_id)
        self._user_states.pop(chat_id, None)
        self._send_menu(chat_id)

    def _cmd_status(self, chat_id):
        import subprocess, shutil
        xray_bin = shutil.which("xray") or "/usr/local/bin/xray"
        try:
            r = subprocess.run(["pgrep", "-f", "xray"], capture_output=True, text=True, timeout=5)
            running = r.returncode == 0
        except:
            running = False
        try:
            vr = subprocess.run([xray_bin, "version"], capture_output=True, text=True, timeout=5)
            ver = vr.stdout.split()[1] if vr.returncode == 0 and len(vr.stdout.split()) > 1 else "?"
        except:
            ver = "?"
        conn = self.get_db()
        ib_count = conn.execute("SELECT COUNT(*) FROM inbounds").fetchone()[0]
        cl_count = conn.execute("SELECT COUNT(*) FROM clients").fetchone()[0]
        conn.close()
        port = self.get_setting("panel_port", "8443")
        status = "🟢 Running" if running else "🔴 Stopped"
        self.send(
            f"📊 <b>Server Status</b>\n\n"
            f"Xray: {status}\n"
            f"Version: <code>{ver}</code>\n"
            f"Inbounds: {ib_count}\n"
            f"Clients: {cl_count}\n"
            f"Panel port: {port}",
            chat_id,
            reply_markup={"inline_keyboard": [[{"text": "◀️ Menu", "callback_data": "menu"}]]}
        )

    def _cmd_list(self, chat_id):
        conn = self.get_db()
        rows = conn.execute("SELECT id, protocol, port, remark, enabled FROM inbounds ORDER BY id").fetchall()
        conn.close()
        if not rows:
            self.send("📋 No inbounds.", chat_id,
                      reply_markup={"inline_keyboard": [[{"text": "◀️ Menu", "callback_data": "menu"}]]})
            return
        lines = ["📋 <b>Inbounds</b>\n"]
        for r in rows:
            st = "🟢" if r["enabled"] else "🔴"
            lines.append(f"{st} <b>#{r['id']}</b> {r['protocol'].upper()} :{r['port']} — {r['remark'] or '-'}")
        self.send("\n".join(lines), chat_id,
                  reply_markup={"inline_keyboard": [[{"text": "◀️ Menu", "callback_data": "menu"}]]})

    def _cmd_create_start(self, chat_id):
        kb = {"inline_keyboard": [
            [{"text": p["label"], "callback_data": f"preset_{k}"}]
            for k, p in PRESETS.items()
        ]}
        self.send("➕ <b>Create Inbound</b>\n\nSelect preset:\n\n<i>Send /cancel to abort</i>", chat_id, reply_markup=kb)

    def _cmd_create_preset(self, chat_id, preset_name):
        if preset_name not in PRESETS:
            self.send("❌ Unknown preset.", chat_id)
            return
        self._user_states[chat_id] = {"action": "create_ib_port", "preset": preset_name}
        self.send(f"Selected: <b>{PRESETS[preset_name]['label']}</b>\n\n🔌 Enter port (e.g. 443):\n\n<i>/cancel to abort</i>", chat_id)

    def _cmd_chpass_start(self, chat_id):
        self._user_states[chat_id] = {"action": "chpass_old"}
        self.send("🔑 Enter current password:\n\n<i>/cancel to abort</i>", chat_id)

    def _cmd_chport_start(self, chat_id):
        port = self.get_setting("panel_port", "8443")
        self._user_states[chat_id] = {"action": "chport"}
        self.send(f"🔧 Current panel port: <b>{port}</b>\n\nEnter new port:\n\n<i>/cancel to abort</i>", chat_id)

    def _cmd_help(self, chat_id):
        self.send(
            "📖 <b>Commands</b>\n\n"
            "/menu — Main menu\n"
            "/status — Server status\n"
            "/list — List inbounds\n"
            "/cancel — Cancel current action\n"
            "/help — This message",
            chat_id,
            reply_markup={"inline_keyboard": [[{"text": "◀️ Menu", "callback_data": "menu"}]]}
        )
