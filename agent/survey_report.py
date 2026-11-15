"""Summarise results.jsonl for the user-testing evidence appendix."""
import json, os, collections, statistics
path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results.jsonl")
fb, sv = [], []
for line in open(path, encoding="utf-8"):
    r = json.loads(line); (fb if r["type"] == "feedback" else sv).append(r)
users = {r["user"] for r in fb + sv}
print(f"Participants: {len(users)} | verdict votes: {len(fb)} | surveys: {len(sv)}")
voted = [r for r in fb if r["agree"] is not None]
if voted:
    print(f"Agreement with AI verdict: {sum(r['agree'] for r in voted)}/{len(voted)} = {100*sum(r['agree'] for r in voted)/len(voted):.0f}%")
    print("Avg AI latency: %.1f s" % statistics.mean(r["latency_s"] for r in fb))
    dis = collections.Counter(r["source"] for r in voted if not r["agree"])
    if dis: print("Most disputed:", dict(dis.most_common(5)))
if sv:
    for k in ("clarity", "fix", "accuracy"):
        print(f"{k:9s}: avg {statistics.mean(r[k] for r in sv):.1f}/5")
    print("Would use:", dict(collections.Counter(r["use"] for r in sv)))
    print("\nComments:")
    for r in sv:
        if r.get("comment"): print(" -", r["comment"])
