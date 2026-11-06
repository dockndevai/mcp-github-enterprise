---
name: github-enterprise-admin
description: Operate GitHub Enterprise (Cloud & Server) safely through the mcp-github-enterprise server — org/repo/team/member management, rulesets, security alerts, and Actions. Use when setting up a new enterprise or org, hardening an org's security posture, triaging secret-scanning/Dependabot/code-scanning alerts, applying branch protection or rulesets, or running any destructive org operation. Carries the secure-setup template, the org-policy baseline, and the guardrails (access modes, org scoping, protected orgs, delete gating, confirmation, dry-run, audit).
---

# Administering GitHub Enterprise safely

This server governs GitHub Enterprise from an AI agent with the suite's **safe-by-default** model: read-only until you deliberately raise the mode, every org pinned by allowlist, destructive ops double-gated, secrets never returned. This skill is the operator's playbook — the setup template, the hardening baseline, and the rules for not causing an incident.

## The guardrails (how this server protects you)

| Control | Env | Effect |
|---|---|---|
| Access mode | `GHE_MODE` | `read-only` (default) → `read-write` → `admin`. A tool is **not even advertised** above the mode. |
| Org allowlist | `GHE_ORG_ALLOWLIST` | Only these orgs can be touched. Empty = every org the token sees — pin it. |
| Protected orgs | `GHE_PROTECTED_ORGS` | Read forever, mutate never — regardless of mode. |
| Delete gate | `GHE_ALLOW_DELETE` | Destructive ops (`delete_repository`, `remove_member`, `delete_team`, `delete_org_ruleset`, `delete_webhook`) need this **and** admin mode **and** a typed confirmation. |
| Confirmation | `GHE_REQUIRE_CONFIRMATION` | High-impact ops must echo the exact target (`org/repo`, username, slug, id). |
| Dry-run | `GHE_DRY_RUN` | Writes are validated + logged, never sent. |
| Audit | `GHE_AUDIT_LOG` | One JSON line per guarded op to stderr — ship it to your SIEM. |
| AI risk gate | `GHE_GUARD_MODE` | Optional laya-guard pass on mutating ops; only tightens, fails closed. |

**Operating principle:** scope with GitHub's own RBAC (a fine-grained PAT or a least-privilege App installation) *first*; these flags are defence in depth, not the primary control. Start read-only, raise the mode for one task, lower it again.

## Token setup (least privilege)

Prefer a **fine-grained PAT** or a **GitHub App installation token** over a classic PAT. Grant only what the task needs:

- **Read/audit:** org `members:read`, `administration:read`, repo `metadata:read`, `secret_scanning_alerts:read`, Dependabot/code-scanning `:read`.
- **Hardening:** add org `administration:write` (org settings, Actions policy) and repo `administration:write` (branch protection, security settings).
- **Enterprise audit log:** classic PAT with `read:audit_log`, and set `GHE_ENTERPRISE`.

GHES (self-hosted): set `GHE_API_URL=https://HOST/api/v3`. Cloud: leave it at `https://api.github.com`.

Validate wiring with `whoami` before anything else.

## Secure-setup template (new enterprise / org)

Call `recommend_enterprise_setup` for the machine-readable version. The staged checklist:

**Enterprise level**
1. Enforce **SSO/SAML + SCIM** — central identity, instant deprovisioning, IdP MFA.
2. Require **2FA** at the enterprise policy (covers every org; no opt-out).
3. Configure an **IP allow list** (and enable it for installed GitHub Apps).
4. Set the enterprise **Actions policy** — allowed actions, fork-PR approval, default workflow token = **read**.
5. Restrict **repo creation & visibility-change** policies (no accidental public exposure).
6. Stream the **enterprise audit log + git events** to your SIEM.

**Organization level**
7. `assess_org_posture` → `harden_org_settings` — 2FA, base **read** permission, secret scanning + push protection, Dependabot, no public-repo creation, no private forks.
8. Assign **security managers** (least-privilege triage role).
9. Define **org rulesets** — required PR review, signed commits, block force-push on default branches.
10. Pin **allowed actions** and **runner groups**; never expose default self-hosted runners to public repos.

**Repository level**
11. Protect default + release branches (`protect_branch` or a ruleset): reviews, status checks, linear history.
12. Enable **code scanning** (CodeQL default setup) and **Dependabot security updates**.
13. CI credentials as encrypted secrets or **OIDC** — never committed.

## The org-policy baseline (what `harden_org_settings` applies)

```
default_repository_permission: read            # least privilege, not write/admin
members_can_create_public_repositories: false  # no accidental public exposure
members_can_fork_private_repositories: false   # contain copies of sensitive code
web_commit_signoff_required: true              # authorship/DCO trail
secret_scanning_enabled_for_new_repositories: true
secret_scanning_push_protection_enabled_for_new_repositories: true   # block at push, don't just report
dependabot_alerts_enabled_for_new_repositories: true
dependabot_security_updates_enabled_for_new_repositories: true
dependency_graph_enabled_for_new_repositories: true
```

**2FA enforcement** is the one high-severity control the REST API does not toggle — it must be set in the org/enterprise authentication UI (or via SSO policy). `assess_org_posture` reports it so you know; it cannot flip it for you.

## Standard flows

**Harden an org**
1. `assess_org_posture { org }` → read the grade and the failing high-severity findings.
2. Dry-run: set `GHE_DRY_RUN=true`, call `harden_org_settings { org }`, read the intended PATCH.
3. Apply: clear dry-run, raise to `read-write`, call `harden_org_settings` (confirm the elicitation).
4. Re-run `assess_org_posture` to confirm the grade moved. Lower the mode again.

**Triage security alerts** — `list_secret_scanning_alerts` (secret values are dropped), `list_dependabot_alerts`, `list_code_scanning_alerts`, filtered by `state: open`. Rank by severity; open issues/PRs in the owning repo.

**Protect branches** — `protect_branch { org, repo, branch }` applies required reviews + no force-push by default; or `create_org_ruleset` to do it org-wide in one object.

## Guardrails for destructive work (read before any delete)

- Deletes are **irreversible** on GitHub (a deleted repo is recoverable only for a short window; members/teams/rulesets are not). Treat every `delete_*`/`remove_*` as permanent.
- Required to proceed: `GHE_MODE=admin` **＋** `GHE_ALLOW_DELETE=true` **＋** the typed `confirm` matching the exact target **＋** the human elicitation prompt. Do not disable `GHE_REQUIRE_CONFIRMATION` for convenience.
- Always **dry-run first** (`GHE_DRY_RUN=true`) and read back the target. Never pass a `confirm` value you assembled from a list response without checking it names the right thing.
- Never remove the **last org owner** or delete a **protected org's** resources — scope those orgs into `GHE_PROTECTED_ORGS`.
- `remove_member` revokes all access immediately; prefer converting to outside collaborator or suspending via SSO when you only need to pause access.

## Secrets

The server redacts webhook `config.secret`/`token`/`password` and drops secret-scanning `secret` values before returning. When you create a webhook, pass the signing `secret` — it is sent to GitHub and never echoed. Never paste a real secret into a tool argument that isn't the write-only `secret` field, and never ask this server to print one back.

See the sibling **github-actions-optimization** skill for CI pipeline speed, caching, and self-hosted runners on Kubernetes.
