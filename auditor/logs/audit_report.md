# GitHub Actions Security Audit Report

**Generated:** 2026-06-12T09:26:50.238563Z
**Target:** /tmp/target_repo
**Workflow files scanned:** 4
**Total findings:** 4
**Rules triggered:** 2/20

## Severity Breakdown

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 0 |
| 🟡 Medium | 2 |
| 🟢 Low | 2 |

## Findings by Category

| Category | Count |
|----------|-------|
| configuration | 4 |

## Detailed Findings

### GHA-SEC-015: Overly Broad Workflow Triggers
**Severity:** low | **Count:** 2

**Affected files:**
- `integration-tests.yml` (line 1)
- `ci.yml` (line 1)

### GHA-SEC-019: No Job-Level Timeout
**Severity:** medium | **Count:** 2

**Affected files:**
- `integration-tests.yml` (line 1)
- `ci.yml` (line 1)
