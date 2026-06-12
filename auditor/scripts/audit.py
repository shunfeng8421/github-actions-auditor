"""Core audit engine: scan GitHub Actions workflow files against security rules."""
import json
import os
import re
import sys
import hashlib
import argparse
from datetime import datetime
from pathlib import Path

try:
    import yaml
except ImportError:
    print("PyYAML required: pip install pyyaml", file=sys.stderr)
    sys.exit(1)

def parse_rules(rules_path):
    """Parse the github-actions-security-rules.txt into structured rules."""
    rules = []
    current = None

    with open(rules_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.rstrip()

            if line.startswith("#") or line.startswith("==") or line.startswith("---") or not line.strip():
                continue

            if line.startswith("rule_id:"):
                if current:
                    rules.append(current)
                current = {"rule_id": line.split(":", 1)[1].strip()}
            elif current is not None:
                if ":" in line:
                    key, val = line.split(":", 1)
                    key = key.strip()
                    val = val.strip().strip('"')
                    if key == "tags":
                        current[key] = [t.strip() for t in val.strip("[]").split(",")]
                    elif key == "detection":
                        current[key] = {"methods": [], "patterns": []}
                    else:
                        current[key] = val
                elif line.strip().startswith("-"):
                    item = line.strip()[1:].strip().strip('"')
                    detection = current.setdefault("detection", {})
                    if any(c in item for c in "\\*+?[](){}^$"):
                        detection.setdefault("patterns", []).append(item)
                    else:
                        detection.setdefault("methods", []).append(item)

    if current:
        rules.append(current)

    return rules

def find_workflow_files(target_dir):
    """Find all .github/workflows/*.yml files in the target directory."""
    files = []
    workflow_dir = Path(target_dir) / ".github" / "workflows"
    if workflow_dir.exists():
        for f in workflow_dir.rglob("*"):
            if f.is_file() and f.suffix in (".yml", ".yaml"):
                files.append(str(f))
    return files

def load_yaml_safe(filepath):
    """Load a YAML file and return parsed content with raw text."""
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            raw = f.read()
        parsed = yaml.safe_load(raw)
        return raw, parsed
    except Exception as e:
        return None, None

def scan_workflow(filepath, raw, parsed, rules):
    """Scan a single workflow file against all security rules."""
    findings = []
    filename = Path(filepath).name

    for rule in rules:
        rule_id = rule["rule_id"]
        patterns = rule.get("detection", {}).get("patterns", [])
        matched = False
        match_detail = ""

        for pattern in patterns:
            try:
                m = re.search(pattern, raw, re.IGNORECASE | re.MULTILINE)
                if m:
                    matched = True
                    match_detail = m.group(0)[:100]
                    break
            except re.error:
                continue

        # Special rule checks that require parsed YAML
        if not matched and parsed:
            matched, match_detail = check_parsed_rule(rule, parsed, filepath)

        if matched:
            line_num = raw[:raw.find(match_detail)].count("\n") + 1 if match_detail in raw else 1
            finding = {
                "id": hashlib.md5(f"{rule_id}:{filepath}:{line_num}".encode()).hexdigest()[:12],
                "rule_id": rule_id,
                "rule_name": rule.get("name", ""),
                "severity": rule.get("severity", "unknown"),
                "severity_weight": int(rule.get("severity_weight", 0)),
                "category": rule.get("category", ""),
                "file": filepath,
                "line": line_num,
                "match": match_detail[:200],
                "confidence": rule.get("confidence", "low"),
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "fix_guidance": rule.get("fix", ""),
                "known_exploits": rule.get("known_exploits", ""),
            }
            findings.append(finding)

            # Additional pattern matches for the same file
            for pattern in patterns[1:]:
                try:
                    for m in re.finditer(pattern, raw, re.IGNORECASE | re.MULTILINE):
                        line_num = raw[:m.start()].count("\n") + 1
                        extra_finding = dict(finding)
                        extra_finding["id"] = hashlib.md5(f"{rule_id}:{filepath}:{m.start()}".encode()).hexdigest()[:12]
                        extra_finding["line"] = line_num
                        extra_finding["match"] = m.group(0)[:200]
                        findings.append(extra_finding)
                except re.error:
                    continue

    return findings

def check_parsed_rule(rule, parsed, filepath):
    """Special checks that require understanding the parsed YAML structure."""
    rule_id = rule.get("rule_id", "")

    # GHA-SEC-004: permissions: write-all check
    if rule_id == "GHA-SEC-004":
        if isinstance(parsed, dict):
            perms = parsed.get("permissions", None)
            if perms == "write-all":
                return True, "permissions: write-all"
            if perms is None:
                return True, "no permissions key at workflow level"

    # GHA-SEC-005: missing permissions top-level
    if rule_id == "GHA-SEC-005":
        if isinstance(parsed, dict) and "permissions" not in parsed:
            # This is already caught by GHA-SEC-004; avoid duplicate
            pass

    # GHA-SEC-006: pull_request_target check
    if rule_id == "GHA-SEC-006":
        if isinstance(parsed, dict):
            triggers = parsed.get("on", parsed.get(True, None))
            # Check various trigger forms
            if triggers == "pull_request_target":
                return True, "pull_request_target trigger"
            if isinstance(triggers, dict):
                if "pull_request_target" in triggers:
                    return True, "pull_request_target trigger"
            if isinstance(triggers, list):
                if "pull_request_target" in triggers:
                    return True, "pull_request_target trigger"

    # GHA-SEC-015: broad triggers
    if rule_id == "GHA-SEC-015":
        if isinstance(parsed, dict):
            triggers = parsed.get("on", parsed.get(True, None))
            if isinstance(triggers, dict):
                if "push" in triggers and triggers["push"] is None:
                    return True, "push trigger without filter"
                if "pull_request" in triggers and triggers["pull_request"] is None:
                    return True, "pull_request trigger without filter"

    # GHA-SEC-019: no timeout-minutes
    if rule_id == "GHA-SEC-019":
        if isinstance(parsed, dict):
            jobs = parsed.get("jobs", {})
            if isinstance(jobs, dict):
                for job_name, job_def in jobs.items():
                    if isinstance(job_def, dict) and "timeout-minutes" not in job_def:
                        return True, f"job '{job_name}' has no timeout-minutes"

    return False, ""

def scan_echo_secrets(filepath, raw):
    """Specialized scan for echo/print of secrets (GHA-SEC-008)."""
    findings = []
    if not raw:
        return findings

    patterns = [
        (r'echo\s+.*\$\{\{\s*secrets\.\w+', "echo of secret variable"),
        (r'print\(.*\$\{\{\s*secrets\.\w+', "print of secret variable"),
        (r'(cat|tee)\s+.*\$\{\{\s*secrets\.\w+', "cat/tee of secret variable"),
        (r'Set-Alias.*\$\{\{\s*secrets\.\w+|\$env:.*\$env:', "PowerShell secret exposure"),
    ]

    for pattern, desc in patterns:
        for m in re.finditer(pattern, raw, re.IGNORECASE | re.MULTILINE):
            line_num = raw[:m.start()].count("\n") + 1
            finding = {
                "id": hashlib.md5(f"GHA-SEC-008:{filepath}:{m.start()}".encode()).hexdigest()[:12],
                "rule_id": "GHA-SEC-008",
                "rule_name": "Echo/Print of Secrets",
                "severity": "critical",
                "severity_weight": 100,
                "category": "secrets",
                "file": filepath,
                "line": line_num,
                "match": m.group(0)[:200],
                "confidence": "critical",
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "fix_guidance": "Never echo or print secret values. Use ::add-mask:: to register secrets.",
            }
            findings.append(finding)

    return findings

def scan_hardcoded_secrets(filepath, raw):
    """Specialized scan for hardcoded credentials in workflow files (GHA-SEC-009)."""
    findings = []
    if not raw:
        return findings

    patterns = [
        (r'(?:TOKEN|KEY|SECRET|PASSWORD|CREDENTIAL)\s*:\s*["\x27](?!\$\{\{)(\w{12,})["\x27]', "hardcoded credential"),
        (r'(?:token|key|secret|password)\s*=\s*["\x27](?!\$\{\{)(\w{12,})["\x27]', "hardcoded credential in env"),
        (r'eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}', "JWT token exposed"),
        (r'(?:AKIA|ASIA)[A-Z0-9]{16}', "AWS access key exposed"),
        (r'ghp_[A-Za-z0-9]{36}', "GitHub personal access token"),
        (r'gho_[A-Za-z0-9]{36}', "GitHub OAuth token"),
        (r'(?:npm_[A-Za-z0-9]{36})', "NPM token"),
    ]

    for pattern, desc in patterns:
        for m in re.finditer(pattern, raw, re.IGNORECASE):
            line_num = raw[:m.start()].count("\n") + 1
            finding = {
                "id": hashlib.md5(f"GHA-SEC-009:{filepath}:{m.start()}".encode()).hexdigest()[:12],
                "rule_id": "GHA-SEC-009",
                "rule_name": "Hardcoded Secrets in Workflow",
                "severity": "critical",
                "severity_weight": 100,
                "category": "secrets",
                "file": filepath,
                "line": line_num,
                "match": desc,
                "confidence": "critical",
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "fix_guidance": "Move to GitHub Secrets: Settings > Secrets and variables > Actions",
            }
            findings.append(finding)

    return findings

def main():
    parser = argparse.ArgumentParser(description="GitHub Actions security auditor")
    parser.add_argument("--target", required=True, help="Target repo directory")
    parser.add_argument("--rules", required=True, help="Rules file path")
    parser.add_argument("--output", default="auditor/findings/", help="Output directory for findings")
    parser.add_argument("--log", default="auditor/logs/events.jsonl", help="Event log path")
    args = parser.parse_args()

    if not os.path.exists(args.target):
        print(f"ERROR: Target directory not found: {args.target}", file=sys.stderr)
        sys.exit(1)

    # Parse rules
    rules = parse_rules(args.rules)
    print(f"Loaded {len(rules)} audit rules")

    # Find workflow files
    workflow_files = find_workflow_files(args.target)
    if not workflow_files:
        print("No .github/workflows/*.yml files found in target")
        # Still write empty results
        workflow_files = []

    print(f"Found {len(workflow_files)} workflow files to scan")

    # Scan all files
    all_findings = []

    for filepath in workflow_files:
        raw, parsed = load_yaml_safe(filepath)
        if raw is None:
            print(f"  SKIP: {filepath} (could not parse)", file=sys.stderr)
            continue

        # Rule-based scan
        findings = scan_workflow(filepath, raw, parsed, rules)
        all_findings.extend(findings)

        # Special scans
        if raw:
            echo_findings = scan_echo_secrets(filepath, raw)
            all_findings.extend(echo_findings)

            secret_findings = scan_hardcoded_secrets(filepath, raw)
            all_findings.extend(secret_findings)

    # Deduplicate and sort
    seen = set()
    unique = []
    for f in all_findings:
        if f["id"] not in seen:
            seen.add(f["id"])
            unique.append(f)

    unique.sort(key=lambda x: x.get("severity_weight", 0), reverse=True)

    # Limit findings
    MAX_FINDINGS = 500
    unique = unique[:MAX_FINDINGS]

    # Write findings
    os.makedirs(args.output, exist_ok=True)
    findings_file = os.path.join(args.output, "findings.jsonl")
    summary_file = os.path.join(args.output, "findings_summary.json")

    with open(findings_file, "w", encoding="utf-8") as f:
        for finding in unique:
            f.write(json.dumps(finding, ensure_ascii=False) + "\n")

    # Summary
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    category_counts = {}
    for f in unique:
        sev = f.get("severity", "low")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        cat = f.get("category", "unknown")
        category_counts[cat] = category_counts.get(cat, 0) + 1

    repo_name = Path(args.target).name
    summary = {
        "target": args.target,
        "repo": repo_name,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "workflow_files_scanned": len(workflow_files),
        "total_findings": len(unique),
        "by_severity": severity_counts,
        "by_category": category_counts,
        "rules_triggered": len(set(f["rule_id"] for f in unique)),
    }

    with open(summary_file, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    # Log event
    os.makedirs(os.path.dirname(args.log), exist_ok=True)
    event = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "workflow": "audit",
        "event": "audit_complete",
        "data": summary
    }
    with open(args.log, "a", encoding="utf-8") as f:
        f.write(json.dumps(event, ensure_ascii=False) + "\n")

    print(f"Audit complete: {len(unique)} findings")
    print(f"  Critical: {severity_counts.get('critical', 0)}, High: {severity_counts.get('high', 0)}, "
          f"Medium: {severity_counts.get('medium', 0)}, Low: {severity_counts.get('low', 0)}")

if __name__ == "__main__":
    main()
