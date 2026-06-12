# GitHub Actions Security Audit Report

**Generated:** 2026-06-12T09:06:27.257162Z
**Target:** /tmp/target_repo
**Workflow files scanned:** 46
**Total findings:** 51
**Rules triggered:** 4/20

## Severity Breakdown

| Severity | Count |
|----------|-------|
| 🔴 Critical | 6 |
| 🟠 High | 0 |
| 🟡 Medium | 42 |
| 🟢 Low | 3 |

## Findings by Category

| Category | Count |
|----------|-------|
| configuration | 45 |
| permissions | 6 |

## Detailed Findings

### GHA-SEC-004: Overly Permissive GITHUB_TOKEN (write-all)
**Severity:** critical | **Count:** 4

**Affected files:**
- `studio-e2e-test.yml` (line 1)
- `label_prs.yml` (line 1)
- `auto-label-issues.yml` (line 1)
- `mirror.yml` (line 1)

### GHA-SEC-006: Secrets Passed to Forked PR Workflows
**Severity:** critical | **Count:** 2

**Affected files:**
- `label_prs.yml` (line 1)
- `external-pr-comment.yml` (line 1)

### GHA-SEC-015: Overly Broad Workflow Triggers
**Severity:** low | **Count:** 3

**Affected files:**
- `studio-e2e-test.yml` (line 1)
- `docs-lint-v2.yml` (line 1)
- `studio-docker-build.yml` (line 1)

### GHA-SEC-019: No Job-Level Timeout
**Severity:** medium | **Count:** 42

**Affected files:**
- `avoid-typos.yml` (line 1)
- `studio-e2e-test.yml` (line 1)
- `update-js-libs.yml` (line 1)
- `docs-lint-v2-comment.yml` (line 1)
- `typecheck.yml` (line 1)
- ... and 37 more
