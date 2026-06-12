# GitHub Actions Security Auditor \U0001f510

Automated security audit pipeline for GitHub Actions workflows. Scans `.github/workflows/*.yml` files, applies security fixes, and submits pull requests.

**First-mover advantage:** Nobody else is doing automated security-fix PRs for GitHub Actions workflows yet. GitHub is actively promoting supply chain security — your PRs will be prioritized for merging.

## Architecture

```
Discover -> Audit -> Fix & PR -> Track -> Daily Report
 (weekly)   (label)   (label)   (every 4h)   (daily)
```

## 20 Security Rules

| # | Rule | Severity |
|---|------|----------|
| 1 | Unpinned Action Version (use commit SHA) | high |
| 2 | Unpinned Docker Image | high |
| 3 | Deprecated Node.js 12 Action | medium |
| 4 | Overly Permissive GITHUB_TOKEN (write-all) | critical |
| 5 | Missing Token Permission Restriction | high |
| 6 | Secrets Passed to Forked PR Workflows | critical |
| 7 | Missing Environment Protection Rules | medium |
| 8 | Echo/Print of Secrets | critical |
| 9 | Hardcoded Secrets in Workflow | critical |
| 10 | Secrets in Artifacts | high |
| 11 | Script Injection via Untrusted Input | critical |
| 12 | Untrusted Checkout Without Caution | high |
| 13 | Dangerous Workflow Run Trigger | medium |
| 14 | Missing Concurrency Group | medium |
| 15 | Overly Broad Workflow Triggers | low |
| 16 | Missing Condition on Sensitive Steps | high |
| 17 | Unverified Third-Party Action | high |
| 18 | Full Git History Clone | low |
| 19 | No Job-Level Timeout | medium |
| 20 | OIDC Not Used for Cloud Auth | medium |

See `auditor/rules/github-actions-security-rules.txt` for full rule definitions.

## Auto-Fix Capabilities

The `fix.py` script automatically applies these fixes:

- **Pin action versions:** Replaces `@v4`/`@v3`/`@main` with commit SHAs
- **Add permissions block:** Inserts `permissions: {}` with minimal scopes
- **Add concurrency group:** Prevents race conditions
- **Add job timeouts:** Sets `timeout-minutes: 15` on every job
- **Remove secret exposure:** Comments out `echo ${{ secrets.X }}` lines

## Pipeline

### 1. Discover (weekly)
Searches GitHub for active repos with `.github/workflows/*.yml` files.

### 2. Audit (on `audit-ready` label)
Clones target repo, scans all workflow YAML files against 20 security rules, generates report.

### 3. Fix & PR (on `fix-ready` label)
Applies auto-fixes to workflow files, forks the repo, commits changes, and opens a PR.

### 4. Track (every 4 hours)
Monitors submitted PRs for merge/close status changes.

### 5. Daily Report (daily 22:00 UTC)
Generates daily summary: repos audited, findings, PR scorecard.

## Usage

1. Push this repo to GitHub
2. Set up secrets:
   - `GITHUB_TOKEN` — auto-provided by GitHub Actions
3. Enable GitHub Actions in repo settings

### Manual Triggers

| Workflow | Trigger |
|----------|---------|
| Discover | `workflow_dispatch` or weekly cron |
| Audit | Add `audit-ready` label to issue |
| Fix & PR | Add `fix-ready` label to issue |
| Track | Every 4 hours automatically |
| Daily Report | Daily 22:00 UTC automatically |

### Quick Start

```bash
# Local audit of any repo
git clone https://github.com/target/repo /tmp/target_repo
python auditor/scripts/audit.py \
  --target /tmp/target_repo \
  --rules auditor/rules/github-actions-security-rules.txt

# Dry-run auto-fix (see what would change)
python auditor/scripts/fix.py \
  --target /tmp/target_repo \
  --repo "target/repo" \
  --dry-run

# Apply fixes and create PR (requires GITHUB_TOKEN)
python auditor/scripts/fix.py \
  --target /tmp/target_repo \
  --repo "target/repo" \
  --create-pr
```

## Directory Structure

```
github-actions-auditor/
  .github/workflows/    # 5 GitHub Actions workflows
  auditor/
    rules/              # 20 security rule definitions
    scripts/            # Python automation scripts
    logs/               # Event logs, tracking data
    findings/           # Audit finding results
```

## Why This Matters

- **Every repo** on GitHub has `.github/workflows/*.yml` — millions of targets
- **GitHub is pushing supply chain security** — your PRs get prioritized
- **First-mover advantage** — nobody is doing automated fix PRs yet
- **High merge rate** — security hardening PRs are rarely controversial

## Credits

Inspired by the [blockchain-auditor](https://github.com/shunfeng8421/blockchain-auditor) bot architecture and [xiaolai/nlpm](https://github.com/xiaolai/nlpm).
