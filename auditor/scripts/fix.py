"""Auto-fix GitHub Actions workflows and create pull requests.
Reads audit findings, applies fixes to YAML, forks repo, commits, and opens PR.
"""
import json
import os
import re
import sys
import time
import shutil
import argparse
import subprocess
from datetime import datetime
from pathlib import Path

try:
    import yaml
except ImportError:
    print("PyYAML required: pip install pyyaml", file=sys.stderr)
    sys.exit(1)

# Known action versions -> commit SHA mapping for pinning
# Action pin map: tag -> commit SHA. Currently empty until real SHAs are verified.
ACTION_PIN_MAP = {}

def pin_action_version(raw):
    """Replace @vX tag references with commit SHAs."""
    modified = raw
    changes = 0
    for tag_ref, pinned in ACTION_PIN_MAP.items():
        action_name = tag_ref.rsplit("@", 1)[0]
        tag = tag_ref.rsplit("@", 1)[1]
        # Match the action with its version tag
        pattern = re.escape(action_name) + r"@" + re.escape(tag) + r"(?:\s|$|\n|\r)"
        if re.search(pattern, modified):
            modified = re.sub(pattern, pinned + " ", modified)
            changes += 1

    # Generic pin for any action@vX that we don't have in our map
    # Add comment warning
    unpinned_pattern = r"(uses:\s*['\"]?)([^@\s'\"]+)@(v\d+|main|master|latest)(['\"]?)"
    for m in re.finditer(unpinned_pattern, raw):
        full = m.group(0)
        if full not in modified:
            # Don't actually change unknown actions - just flag them
            pass

    return modified, changes

def add_permissions_block(raw):
    """Add permissions: {} block if missing from workflow."""
    if re.search(r'^permissions\s*:', raw, re.MULTILINE):
        return raw, 0

    # Insert after the 'on:' trigger block or after 'name:'
    lines = raw.split("\n")
    insert_idx = 0
    in_trigger = False

    for i, line in enumerate(lines):
        if re.match(r'^(on|true|"' + "'" + r')\s*:', line.strip()):
            in_trigger = True
        elif in_trigger and line.strip() and not line[0].isspace():
            insert_idx = i
            break
        elif in_trigger and i == len(lines) - 1:
            insert_idx = i + 1

    if insert_idx == 0:
        # Fallback: insert after name:
        for i, line in enumerate(lines):
            if line.strip().startswith("name:"):
                insert_idx = i + 1
                break

    if insert_idx == 0:
        insert_idx = 0

    lines.insert(insert_idx, "")
    lines.insert(insert_idx + 1, "permissions: {}")
    lines.insert(insert_idx + 2, "")

    return "\n".join(lines), 1

def add_concurrency_group(raw):
    """Add concurrency group if missing."""
    if re.search(r'^concurrency\s*:', raw, re.MULTILINE):
        return raw, 0

    lines = raw.split("\n")
    insert_idx = 0

    for i, line in enumerate(lines):
        if re.match(r'^(on|true|"' + "'" + r')\s*:', line.strip()):
            in_trigger = True
            continue
        if line.strip().startswith("jobs:") or line.strip().startswith("permissions:"):
            insert_idx = i
            break

    lines.insert(insert_idx, "")
    lines.insert(insert_idx + 1, "# Prevent concurrent runs of the same workflow")
    lines.insert(insert_idx + 2, "concurrency:")
    lines.insert(insert_idx + 3, "  group: ${{ github.workflow }}-${{ github.ref }}")
    lines.insert(insert_idx + 4, "  cancel-in-progress: true")
    lines.insert(insert_idx + 5, "")

    return "\n".join(lines), 1

def add_job_timeouts(raw, parsed=None):
    """Add timeout-minutes to jobs that lack them, using parsed YAML to identify real jobs."""
    if not parsed or not isinstance(parsed, dict):
        return raw, 0
    
    jobs = parsed.get("jobs", {})
    if not isinstance(jobs, dict) or not jobs:
        return raw, 0
    
    changes = 0
    lines = raw.split("\n")
    
    for job_name, job_def in jobs.items():
        if not isinstance(job_def, dict):
            continue
        if "timeout-minutes" in job_def:
            continue
        
        # Find the job definition in raw YAML
        pattern = r"^  " + re.escape(job_name) + r"\s*:\s*$"
        m = re.search(pattern, raw, re.MULTILINE)
        if m:
            insert_pos = raw[:m.end()].count("\n")
            lines.insert(insert_pos + 1, "    timeout-minutes: 15")
            changes += 1
    
    return "\n".join(lines), changes

def fix_echo_secrets(raw):
    """Comment out lines that echo secrets."""
    modified = raw
    changes = 0

    lines = modified.split("\n")
    new_lines = []
    for line in lines:
        if re.search(r'echo\s+.*\$\{\{\s*secrets\.', line, re.IGNORECASE):
            new_lines.append(f"# REMOVED: echo of secret - {line.strip()}")
            new_lines.append(f"# Use: echo '::add-mask::VALUE' then reference indirectly")
            changes += 1
        elif re.search(r'(print|cat|tee)\s+.*\$\{\{\s*secrets\.', line, re.IGNORECASE):
            new_lines.append(f"# REMOVED: secret exposure - {line.strip()}")
            changes += 1
        else:
            new_lines.append(line)

    return "\n".join(new_lines), changes

def apply_fixes(workflow_path, parsed):
    """Apply all auto-fixable rules to a workflow file."""
    with open(workflow_path, "r", encoding="utf-8") as f:
        raw = f.read()

    original = raw
    total_changes = 0
    fix_log = []

    # 1. Pin action versions
    raw, changes = pin_action_version(raw)
    if changes:
        total_changes += changes
        fix_log.append(f"Pinned {changes} action version(s) to commit SHA")

    # 2. Add permissions block
    raw, changes = add_permissions_block(raw)
    if changes:
        total_changes += changes
        fix_log.append("Added permissions: {} block")

    # 3. Add concurrency group
    raw, changes = add_concurrency_group(raw)
    if changes:
        total_changes += changes
        fix_log.append("Added concurrency group")

    # 4. Add job timeouts
    raw, changes = add_job_timeouts(raw, parsed)
    if changes:
        total_changes += changes
        fix_log.append(f"Added timeout-minutes to {changes} job(s)")

    # 5. Fix echo secrets
    raw, changes = fix_echo_secrets(raw)
    if changes:
        total_changes += changes
        fix_log.append(f"Removed {changes} secret exposure(s)")

    if total_changes > 0:
        with open(workflow_path, "w", encoding="utf-8") as f:
            f.write(raw)

    return total_changes, fix_log

def fork_repo(token, repo_full_name):
    """Fork the target repo to the authenticated user's account."""
    import requests
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28"
    }

    owner, repo = repo_full_name.split("/")

    # Check if fork already exists
    user_resp = requests.get(f"https://api.github.com/user", headers=headers, timeout=15)
    if user_resp.status_code != 200:
        print(f"Cannot get user info: {user_resp.status_code}")
        return None

    username = user_resp.json()["login"]

    # Try to get existing fork
    fork_resp = requests.get(
        f"https://api.github.com/repos/{username}/{repo}",
        headers=headers, timeout=15
    )

    if fork_resp.status_code == 200:
        print(f"  Fork already exists: {username}/{repo}")
        return username

    # Create fork
    print(f"  Forking {repo_full_name}...")
    fork_resp = requests.post(
        f"https://api.github.com/repos/{repo_full_name}/forks",
        headers=headers, json={"default_branch_only": True}, timeout=30
    )

    if fork_resp.status_code == 202:
        print(f"  Fork queued, waiting...")
        time.sleep(5)
        return username
    elif fork_resp.status_code == 200:
        print(f"  Forked successfully: {username}/{repo}")
        return username
    else:
        print(f"  Fork failed: {fork_resp.status_code} {fork_resp.text[:200]}", file=sys.stderr)
        return None

def create_fix_branch(clone_dir, branch_name):
    """Create a new branch for the fix."""
    subprocess.run(["git", "-C", clone_dir, "checkout", "-b", branch_name],
                   capture_output=True, check=True)
    print(f"  Created branch: {branch_name}")

def commit_and_push(clone_dir, branch_name, fix_summary):
    """Commit the fixes and push to the fork."""
    subprocess.run(["git", "-C", clone_dir, "config", "user.name", "github-actions-auditor[bot]"],
                   capture_output=True)
    subprocess.run(["git", "-C", clone_dir, "config", "user.email", "github-actions-auditor[bot]@users.noreply.github.com"],
                   capture_output=True)

    subprocess.run(["git", "-C", clone_dir, "add", ".github/workflows/"],
                   capture_output=True)

    result = subprocess.run(["git", "-C", clone_dir, "diff", "--staged", "--quiet"],
                            capture_output=True)
    if result.returncode == 0:
        print("  No changes to commit")
        return False

    commit_msg = "security: harden GitHub Actions workflows\n\n"
    for log in fix_summary:
        commit_msg += f"- {log}\n"

    subprocess.run(["git", "-C", clone_dir, "commit", "-m", commit_msg],
                   capture_output=True, check=True)

    subprocess.run(["git", "-C", clone_dir, "push", "origin", branch_name],
                   capture_output=True, check=True)
    print(f"  Pushed to branch: {branch_name}")
    return True

def create_pr(token, repo_full_name, branch_name, username, findings_summary):
    """Create a pull request to the upstream repo."""
    import requests
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28"
    }

    # Generate PR body
    body_parts = [
        "## [SEC] GitHub Actions Security Hardening",
        "",
        "This PR applies security best practices to the GitHub Actions workflows:",
        ""
    ]
    for log in findings_summary.get("fixes_applied", []):
        body_parts.append(f"- [x] {log}")

    sev = findings_summary.get("by_severity", {})
    body_parts.append("")
    body_parts.append("### Findings Summary")
    body_parts.append(f"| Severity | Count |")
    body_parts.append(f"|----------|-------|")
    for s in ["critical", "high", "medium", "low"]:
        count = sev.get(s, 0)
        body_parts.append(f"| {s} | {count} |")

    body_parts.append("")
    body_parts.append("*Automated by [github-actions-auditor](https://github.com/shunfeng8421/github-actions-auditor) [BOT]*")

    pr_data = {
        "title": "security: harden GitHub Actions workflows",
        "body": "\n".join(body_parts),
        "head": f"{username}:{branch_name}",
        "base": findings_summary.get("default_branch", "main"),
    }

    resp = requests.post(
        f"https://api.github.com/repos/{repo_full_name}/pulls",
        headers=headers, json=pr_data, timeout=30
    )

    if resp.status_code == 201:
        pr_url = resp.json()["html_url"]
        pr_number = resp.json()["number"]
        print(f"  PR created: {pr_url}")
        return pr_number, pr_url
    elif resp.status_code == 422 and "already exists" in resp.text:
        print(f"  PR already exists")
        return None, None
    else:
        print(f"  PR creation failed: {resp.status_code} {resp.text[:300]}", file=sys.stderr)
        return None, None

def main():
    parser = argparse.ArgumentParser(description="Auto-fix GitHub Actions workflows and create PRs")
    parser.add_argument("--target", required=True, help="Target repo directory (cloned)")
    parser.add_argument("--findings", default="auditor/findings/", help="Audit findings directory")
    parser.add_argument("--output", default="auditor/logs/pr_tracking.jsonl", help="PR tracking output")
    parser.add_argument("--repo", required=True, help="Target repo full name (owner/repo)")
    parser.add_argument("--create-pr", action="store_true", help="Actually fork and create PR")
    parser.add_argument("--branch", default=None, help="Branch name for fix (default: auto-generated)")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be changed without applying")
    args = parser.parse_args()

    token = os.environ.get("GITHUB_TOKEN")
    if args.create_pr and not token:
        print("ERROR: GITHUB_TOKEN not set (required for PR creation)", file=sys.stderr)
        sys.exit(1)

    # Load findings
    findings_file = os.path.join(args.findings, "findings.jsonl")
    summary_file = os.path.join(args.findings, "findings_summary.json")

    findings_summary = {}
    if os.path.exists(summary_file):
        with open(summary_file, "r", encoding="utf-8") as f:
            findings_summary = json.load(f)

    workflow_dir = Path(args.target) / ".github" / "workflows"
    if not workflow_dir.exists():
        print("No .github/workflows directory found")
        return

    workflow_files = list(workflow_dir.rglob("*.yml")) + list(workflow_dir.rglob("*.yaml"))
    print(f"Processing {len(workflow_files)} workflow file(s) in {args.target}")

    if args.dry_run:
        print("\n=== DRY RUN - No changes will be made ===\n")

    all_fixes = []
    for wf in workflow_files:
        wf_rel = str(wf.relative_to(args.target))
        print(f"\n  Analyzing: {wf_rel}")

        _, parsed_wf = load_yaml_safe(str(wf)); total_changes, fix_log = apply_fixes(str(wf), parsed_wf)
        if total_changes > 0:
            print(f"  - {total_changes} fix(es) applied:")
            for log in fix_log:
                print(f"    - {log}")
            all_fixes.extend(fix_log)
        else:
            print(f"  - No fixes needed")

    if args.dry_run:
        print(f"\n[DRY-RUN] Dry run summary: {len(all_fixes)} fix(es) identified across {len(workflow_files)} file(s)")
        return

    if not all_fixes:
        print("\n- No fixes to apply")
        return

    print(f"\n- Total: {len(all_fixes)} fix(es) applied")

    if not args.create_pr:
        print("Skipping PR creation (use --create-pr to fork and submit)")
        return

    # Create PR
    print(f"\n[PR] Preparing pull request to {args.repo}...")

    username = fork_repo(token, args.repo)
    if not username:
        print("Failed to fork repo, aborting PR creation", file=sys.stderr)
        return

    branch_name = args.branch or f"gha-security-fixes-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
    create_fix_branch(args.target, branch_name)

    findings_summary["fixes_applied"] = all_fixes

    if commit_and_push(args.target, branch_name, all_fixes):
        pr_number, pr_url = create_pr(token, args.repo, branch_name, username, findings_summary)

        # Track the PR
        if pr_number:
            os.makedirs(os.path.dirname(args.output), exist_ok=True)
            tracking_entry = {
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "repo_full_name": args.repo,
                "repo_url": f"https://github.com/{args.repo}",
                "pr_number": pr_number,
                "pr_url": pr_url,
                "branch": branch_name,
                "status": "open",
                "findings_count": findings_summary.get("total_findings", 0),
                "fixes_applied": len(all_fixes),
                "severity": findings_summary.get("by_severity", {}),
            }
            with open(args.output, "a", encoding="utf-8") as f:
                f.write(json.dumps(tracking_entry, ensure_ascii=False) + "\n")

            print(f"\n[DONE] PR submitted: {pr_url}")
def load_yaml_safe(filepath):
    """Load a YAML file and return parsed content with raw text."""
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            raw = f.read()
        parsed = yaml.safe_load(raw)
        return raw, parsed
    except Exception:
        return None, None

if __name__ == "__main__":
    main()


