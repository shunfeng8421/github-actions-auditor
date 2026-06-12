"""Generate summary statistics for the auditor."""
import json
import os
import argparse
from datetime import datetime

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--events", default="auditor/logs/events.jsonl")
    parser.add_argument("--output", default="auditor/logs/summary.json")
    args = parser.parse_args()

    total_repos = 0
    total_findings = 0
    prs_merged = 0
    prs_tracked = 0
    rules_adopted = set()

    if os.path.exists(args.events):
        with open(args.events, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    try:
                        evt = json.loads(line)
                        data = evt.get("data", {})
                        if evt.get("workflow") == "audit":
                            total_repos += 1
                            total_findings += data.get("total_findings", 0)
                            rules_adopted.add(data.get("rules_triggered", 0))
                        if evt.get("workflow") == "track":
                            prs_merged = data.get("merged", prs_merged)
                            prs_tracked = data.get("tracked", prs_tracked)
                    except json.JSONDecodeError:
                        continue

    summary = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "total_repos_audited": total_repos,
        "total_findings": total_findings,
        "prs_merged": prs_merged,
        "prs_tracked": prs_tracked,
        "rules_adopted": len(rules_adopted),
    }

    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    print(f"Summary written to {args.output}")

if __name__ == "__main__":
    main()
