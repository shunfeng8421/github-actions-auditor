"""Generate human-readable audit report from GitHub Actions findings."""
import json
import os
import glob
import argparse
from datetime import datetime

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--findings", default="auditor/findings/")
    parser.add_argument("--output", default="auditor/logs/audit_report.md")
    args = parser.parse_args()

    finding_files = sorted(glob.glob(os.path.join(args.findings, "*_findings.jsonl")))
    summary_files = sorted(glob.glob(os.path.join(args.findings, "*_summary.json")))
    findings_file = finding_files[-1] if finding_files else os.path.join(args.findings, "findings.jsonl")
    summary_file = summary_files[-1] if summary_files else os.path.join(args.findings, "findings_summary.json")

    if not os.path.exists(summary_file):
        print("No findings to report")
        return

    with open(summary_file, "r", encoding="utf-8") as f:
        summary = json.load(f)

    lines = []
    lines.append("# GitHub Actions Security Audit Report")
    lines.append(f"\n**Generated:** {datetime.utcnow().isoformat()}Z")
    lines.append(f"**Target:** {summary.get('target', 'N/A')}")
    lines.append(f"**Workflow files scanned:** {summary['workflow_files_scanned']}")
    lines.append(f"**Total findings:** {summary['total_findings']}")
    lines.append(f"**Rules triggered:** {summary.get('rules_triggered', 0)}/20")
    lines.append("")

    # Severity breakdown
    lines.append("## Severity Breakdown")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|----------|-------|")
    sev_emoji = {"critical": "\U0001f534", "high": "\U0001f7e0", "medium": "\U0001f7e1", "low": "\U0001f7e2"}
    for sev in ["critical", "high", "medium", "low"]:
        count = summary["by_severity"].get(sev, 0)
        lines.append(f"| {sev_emoji.get(sev, '')} {sev.capitalize()} | {count} |")
    lines.append("")

    # Category breakdown
    cat = summary.get("by_category", {})
    if cat:
        lines.append("## Findings by Category")
        lines.append("")
        lines.append("| Category | Count |")
        lines.append("|----------|-------|")
        for category, count in sorted(cat.items(), key=lambda x: -x[1]):
            lines.append(f"| {category} | {count} |")
        lines.append("")

    # Detailed findings
    if os.path.exists(findings_file):
        lines.append("## Detailed Findings")
        lines.append("")
        with open(findings_file, "r", encoding="utf-8") as f:
            all_findings = [json.loads(line) for line in f if line.strip()]

        by_rule = {}
        for finding in all_findings:
            rid = finding["rule_id"]
            by_rule.setdefault(rid, []).append(finding)

        for rid, findings in sorted(by_rule.items()):
            lines.append(f"### {rid}: {findings[0].get('rule_name', rid)}")
            lines.append(f"**Severity:** {findings[0].get('severity', 'N/A')} | **Count:** {len(findings)}")
            lines.append("")
            lines.append("**Affected files:**")
            files_shown = set()
            for f in findings[:5]:
                fname = f["file"].replace("\\", "/").split("/")[-1]
                if fname not in files_shown:
                    lines.append(f"- `{fname}` (line {f.get('line', '?')})")
                    files_shown.add(fname)
            if len(findings) > 5:
                lines.append(f"- ... and {len(findings) - 5} more")
            lines.append("")

            if findings[0].get("fix_guidance"):
                lines.append(f"**Fix:** {findings[0]['fix_guidance']}")
                lines.append("")

    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    print(f"Report written to {args.output}")

if __name__ == "__main__":
    main()
