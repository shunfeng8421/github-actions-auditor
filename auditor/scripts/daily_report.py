"""Generate daily audit report for GitHub Actions auditor."""
import json
import os
import argparse
from datetime import datetime, timedelta

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--events", default="auditor/logs/events.jsonl")
    parser.add_argument("--findings", default="auditor/findings/")
    parser.add_argument("--tracking", default="auditor/logs/pr_status.jsonl")
    parser.add_argument("--output", default="auditor/logs/daily_report.md")
    args = parser.parse_args()

    today = datetime.utcnow()
    yesterday = today - timedelta(days=1)

    lines = []
    lines.append(f"# GitHub Actions Security Audit - Daily Report {today.strftime('%Y-%m-%d')}")
    lines.append("")

    # Count today's events
    events_today = []
    if os.path.exists(args.events):
        with open(args.events, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    try:
                        evt = json.loads(line)
                        ts = evt.get("timestamp", "")
                        if yesterday.strftime("%Y-%m-%d") in ts or today.strftime("%Y-%m-%d") in ts:
                            events_today.append(evt)
                    except json.JSONDecodeError:
                        continue

    audit_events = [e for e in events_today if e.get("workflow") == "audit"]
    track_events = [e for e in events_today if e.get("workflow") == "track"]
    fix_events = [e for e in events_today if e.get("workflow") == "fix"]

    lines.append("## Pipeline Activity Today")
    lines.append("")
    lines.append("| Workflow | Runs |")
    lines.append("|----------|------|")
    lines.append(f"| Discover | Weekly |")
    lines.append(f"| Audit | {len(audit_events)} |")
    lines.append(f"| Fix & PR | {len(fix_events)} |")
    lines.append(f"| Track | {len(track_events)} |")
    lines.append("")

    # Aggregated findings today
    total_findings = 0
    total_critical = 0
    repos_audited = set()
    for evt in audit_events:
        data = evt.get("data", {})
        total_findings += data.get("total_findings", 0)
        total_critical += data.get("by_severity", {}).get("critical", 0)
        repos_audited.add(data.get("target", ""))

    lines.append("## Audit Results Today")
    lines.append("")
    lines.append(f"- **Repos audited:** {len(repos_audited)}")
    lines.append(f"- **Total findings:** {total_findings}")
    lines.append(f"- **Critical issues:** {total_critical}")
    lines.append("")

    # PR scorecard
    for evt in reversed(track_events):
        if evt.get("event") == "status_check":
            data = evt.get("data", {})
            lines.append("## PR Scorecard")
            lines.append("")
            lines.append("| Metric | Count |")
            lines.append("|--------|-------|")
            lines.append(f"| Contributed | {data.get('contributed', 0)} |")
            lines.append(f"| Open | {data.get('open', 0)} |")
            lines.append(f"| Merged | {data.get('merged', 0)} |")
            lines.append(f"| Closed | {data.get('closed', 0)} |")
            break

    lines.append("")
    lines.append(f"_Report generated at {today.isoformat()}Z by github-actions-auditor_")

    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    print(f"Daily report written to {args.output}")

if __name__ == "__main__":
    main()
