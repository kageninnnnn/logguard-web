"""Summarise bot feedback + surveys for the user-testing evidence appendix.

Cloud bot: export SUPABASE_URL and SUPABASE_SECRET_KEY, then run this script.
Local bot: reads agent/results.jsonl.
"""
import collections, json, os, statistics, urllib.request

url, key = os.environ.get("SUPABASE_URL", "").rstrip("/"), os.environ.get("SUPABASE_SECRET_KEY", "")
if url and key:
    def get(t):
        req = urllib.request.Request(f"{url}/rest/v1/{t}?select=*", headers={"apikey": key, "Authorization": f"Bearer {key}"})
        return json.load(urllib.request.urlopen(req))
    fb, sv = [r for r in get("bot_feedback") if r.get("user_verdict")], get("bot_surveys")
else:
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results.jsonl")
    if not os.path.exists(path):
        raise SystemExit("No results yet: vote under a verdict or finish /survey first.")
    fb, sv = [], []
    for line in open(path, encoding="utf-8"):
        r = json.loads(line); (fb if r["type"] == "feedback" else sv).append(r)

users = {r["user"] for r in fb + sv}
print(f"Participants: {len(users)} | verdict votes: {len(fb)} | surveys: {len(sv)}")
voted = [r for r in fb if r.get("agree") is not None]
if voted:
    ok = sum(1 for r in voted if r["agree"])
    print(f"Agreement with AI verdict: {ok}/{len(voted)} = {100 * ok / len(voted):.0f}%")
    print("Avg AI latency: %.1f s" % statistics.mean(float(r["latency_s"]) for r in fb))
    dis = collections.Counter(r["source"] for r in voted if not r["agree"])
    if dis:
        print("Most disputed:", dict(dis.most_common(5)))
if sv:
    for k in ("clarity", "fix", "accuracy"):
        print(f"{k:9s}: avg {statistics.mean(r[k] for r in sv):.1f}/5")
    print("Would use:", dict(collections.Counter(r["use"] for r in sv)))
    print("\nComments:")
    for r in sv:
        if r.get("comment"):
            print(" -", r["comment"])
