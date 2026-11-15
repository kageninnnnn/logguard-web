"""LogGuard agent: watches sudo/su/sshd via journald, triages with an LLM,
sends real threats to the LogGuard dashboard and to Telegram.

Required env vars:
  LOGGUARD_URL, LOGGUARD_ANON_KEY, LOGGUARD_AGENT_KEY   (shown in the dashboard)
Optional:
  TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID
  OLLAMA_URL (default http://127.0.0.1:11434/api/generate), MODEL_NAME (default qwen2.5:3b)
"""
import json
import os
import re
import subprocess
import sys

import requests

LOGGUARD_URL = os.environ.get("LOGGUARD_URL", "").rstrip("/")
LOGGUARD_ANON_KEY = os.environ.get("LOGGUARD_ANON_KEY", "")
LOGGUARD_AGENT_KEY = os.environ.get("LOGGUARD_AGENT_KEY", "")
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "")
OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://127.0.0.1:11434/api/generate")
MODEL_NAME = os.environ.get("MODEL_NAME", "qwen2.5:3b")

BLUE, PURPLE, GREEN, RED, YELLOW, RESET = "\033[94m", "\033[95m", "\033[92m", "\033[91m", "\033[93m", "\033[0m"
IGNORE_NOISE = re.compile(r"pam_unix\((sudo|su):session\): session (opened|closed)")

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
  "title": "Short incident title in English",
  "explanation": "Clear explanation in English (1-2 sentences)",
  "remediation": "Actionable command or steps in English"
}"""


def analyze(log_line: str) -> dict:
    payload = {"model": MODEL_NAME, "system": SYSTEM_PROMPT,
               "prompt": f"Analyze this log entry:\n{log_line}", "format": "json",
               "stream": False, "options": {"temperature": 0.0, "num_ctx": 1024}}
    try:
        r = requests.post(OLLAMA_URL, json=payload, timeout=30)
        r.raise_for_status()
        return json.loads(r.json().get("response", "{}"))
    except Exception as e:
        print(f"{RED}[!] AI error: {e}{RESET}", file=sys.stderr)
        return {}


def send_dashboard(a: dict, raw: str):
    if not (LOGGUARD_URL and LOGGUARD_AGENT_KEY):
        return
    try:
        r = requests.post(f"{LOGGUARD_URL}/rest/v1/rpc/ingest_alert",
                          headers={"apikey": LOGGUARD_ANON_KEY, "Authorization": f"Bearer {LOGGUARD_ANON_KEY}",
                                   "Content-Type": "application/json"},
                          json={"p_agent_key": LOGGUARD_AGENT_KEY, "p_severity": a.get("severity", "MEDIUM"),
                                "p_title": a.get("title", "Security incident"),
                                "p_explanation": a.get("explanation", ""),
                                "p_remediation": a.get("remediation", ""), "p_raw_log": raw},
                          timeout=10)
        r.raise_for_status()
        print(f"{GREEN}[+] Alert sent to dashboard{RESET}")
    except Exception as e:
        print(f"{RED}[!] Dashboard error: {e}{RESET}", file=sys.stderr)


def send_telegram(a: dict, raw: str):
    if not (TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID):
        return
    icons = {"LOW": "🟢", "MEDIUM": "🟡", "HIGH": "🟠", "CRITICAL": "🔴"}
    sev = a.get("severity", "MEDIUM")
    msg = (f"{icons.get(sev, '⚠️')} *LogGuard Alert: {a.get('title', 'Security incident')}*\n"
           f"*Severity:* `{sev}`\n\n"
           f"🧠 *AI analysis:*\n{a.get('explanation', '')}\n\n"
           f"🛠 *Fix:*\n`{a.get('remediation', 'Check the host')}`\n\n"
           f"📄 *Raw log:*\n`{raw}`")
    try:
        requests.post(f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
                      json={"chat_id": TELEGRAM_CHAT_ID, "text": msg, "parse_mode": "Markdown"}, timeout=10)
        print(f"{GREEN}[+] Alert sent to Telegram{RESET}\n")
    except Exception as e:
        print(f"{RED}[!] Telegram error: {e}{RESET}", file=sys.stderr)


def main():
    print(f"{GREEN}=== LogGuard agent | model: {MODEL_NAME} ==={RESET}")
    print("[*] Watching journald (sudo, su, sshd)...\n")
    proc = subprocess.Popen(["journalctl", "-f", "-n", "0", "-t", "sudo", "-t", "su", "-t", "sshd"],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        for line in proc.stdout:
            line = line.strip()
            if not line or IGNORE_NOISE.search(line):
                continue
            print(f"{BLUE}[LOG]{RESET} {line}")
            print(f"{PURPLE}[AI TRIAGE]{RESET} {MODEL_NAME}...")
            a = analyze(line)
            if not a:
                continue
            sev = a.get("severity", "LOW")
            if a.get("is_threat") and sev in ("MEDIUM", "HIGH", "CRITICAL"):
                print(f"{YELLOW}[THREAT: {sev}]{RESET} {a.get('explanation', '')}")
                send_dashboard(a, line)
                send_telegram(a, line)
            else:
                print(f"{GREEN}[BENIGN]{RESET} {a.get('explanation', '')}\n[-] Suppressed (alert fatigue protection)\n")
    except KeyboardInterrupt:
        proc.terminate()


if __name__ == "__main__":
    main()
