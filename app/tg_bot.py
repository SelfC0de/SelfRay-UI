import json
import time
import threading
import logging
import urllib.request
import urllib.error

logger = logging.getLogger("tg_bot")


class SelfRayBot:
    def __init__(self, get_setting_fn, set_setting_fn, hash_password_fn, get_db_fn, **_):
        self.get_setting = get_setting_fn
        self.set_setting = set_setting_fn
        self.hash_password = hash_password_fn
        self.get_db = get_db_fn
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
            self.stop()
        if not self.token or not self.chat_id:
            return
        self._running = True
        self._thread = threading.Thread(target=self._poll_loop, daemon=True)
        self._thread.start()
        logger.info("Telegram bot started")

    def stop(self):
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)
        self._thread = None

    def _poll_loop(self):
        while self._running:
            if not self.token:
                time.sleep(5)
                continue
            try:
                result = self._api("getUpdates", {"offset": self._offset, "timeout": 10})
                if not self._running:
                    break
                if not result or not result.get("ok"):
                    time.sleep(3)
                    continue
                for update in result.get("result", []):
                    if not self._running:
                        break
                    self._offset = update["update_id"] + 1
                    try:
                        self._handle_update(update)
                    except Exception as e:
                        logger.error(f"Handle update error: {e}")
            except Exception as e:
                logger.error(f"Poll error: {e}")
                time.sleep(3)

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
            [{"text": "🔑 Change Password", "callback_data": "chpass"}, {"text": "🔧 Change Port", "callback_data": "chport"}],
        ]}
        self.send("🏠 <b>SelfRay-UI</b> — Main Menu\n\nChoose an action:", chat_id, reply_markup=kb)

    def _handle_callback(self, cb):
        msg = cb.get("message")
        if not msg:
            return
        chat_id = msg["chat"]["id"]
        if not self._is_admin(chat_id):
            self.answer_callback(cb["id"], "Access denied")
            return
        data = cb.get("data", "")
        self.answer_callback(cb["id"])

        if data == "status":
            self._cmd_status(chat_id)
        elif data == "list":
            self._cmd_list(chat_id)
        elif data == "chpass":
            self._cmd_chpass_start(chat_id)
        elif data == "chport":
            self._cmd_chport_start(chat_id)
        elif data == "menu":
            self._user_states.pop(chat_id, None)
            self._send_menu(chat_id)

    def _handle_state(self, chat_id, text, state):
        action = state.get("action")

        if action == "chpass_old":
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
