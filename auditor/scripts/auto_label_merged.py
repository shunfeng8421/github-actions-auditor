"""Auto-label merged PRs for tracking."""
import json
import os
import argparse

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--tracking", default="auditor/logs/pr_status.jsonl")
    parser.add_argument("--label", default="merged")
    args = parser.parse_args()

    if not os.path.exists(args.tracking):
        return

    merged = []
    with open(args.tracking, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                try:
                    entry = json.loads(line)
                    if entry.get("new_status") == "merged":
                        merged.append(entry)
                except json.JSONDecodeError:
                    continue

    if merged:
        print(f"{len(merged)} merged PR(s) found:")
        for m in merged:
            print(f"  {m['repo_full_name']}#{m['pr_number']} - {m.get('html_url', '')}")

if __name__ == "__main__":
    main()
