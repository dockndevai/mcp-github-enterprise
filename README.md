# mcp-github-enterprise

[![CI](https://github.com/dockndevai/mcp-github-enterprise/actions/workflows/ci.yml/badge.svg)](https://github.com/dockndevai/mcp-github-enterprise/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/@dockndevai/mcp-github-enterprise.svg)](https://www.npmjs.com/package/@dockndevai/mcp-github-enterprise)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A **safe-by-default** [Model Context Protocol](https://modelcontextprotocol.io) server for administering **GitHub Enterprise** (Cloud & Server) from an AI agent — organizations, members, teams, repositories, rulesets, security alerts, and Actions — with a built-in **security-posture baseline** and governance controls so an agent can help run your enterprise without being able to wreck it.

> Part of the [dockndevai](https://dockndevai.github.io) suite of governed infrastructure MCP servers. Read-only by default · org-scoped · audited · human-confirmed.

## Why

Handing an agent an admin token to GitHub is risky: one loose instruction can delete a repo, remove a member, or flip an org public. This server puts the agent behind the same controls you'd give a junior admin:

- **Read-only until you say otherwise.** Tools above the current access mode are *never advertised*.
- **Pinned blast radius.** An org allowlist and protected (read-only-forever) orgs.
- **Destructive ops double-gated.** Admin mode **＋** an explicit delete flag **＋** a typed confirmation **＋** a human prompt. The prompt shows the tool, the exact arguments and a fingerprint; the target's version is pinned across the prompt and the action is refused if it changed; a prompt nobody answers is a refusal.
- **Secrets never leak.** Webhook secrets and secret-scanning values are redacted before anything reaches the model.
- **Everything audited.** A JSON line per operation to stderr.

Plus the part that makes it *useful*, not just safe: it ships an opinionated **security baseline** — `assess_org_posture` scores a live org and `harden_org_settings` applies the fix — and two operator skills (secure setup + Actions optimization).

## Quick start

```bash
# Read-only, against GitHub Enterprise Cloud
GHE_TOKEN=your-token GHE_MODE=read-only npx -y @dockndevai/mcp-github-enterprise
```

Add to **Claude Code**:
```bash
claude mcp add github-enterprise -e GHE_TOKEN="your-token" -e GHE_MODE="read-only" -- npx -y @dockndevai/mcp-github-enterprise
```

GitHub Enterprise **Server**: add `-e GHE_API_URL="https://HOST/api/v3"`. Full client configs (Cursor, Windsurf, Codex, VS Code, Claude Desktop) in [docs/CLIENTS.md](docs/CLIENTS.md).

First call to run: **`whoami`** — confirms the token and base URL are wired correctly.

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `GHE_TOKEN` | — | **Required.** Fine-grained PAT, classic PAT, or App installation token. Least privilege. |
| `GHE_API_URL` | `https://api.github.com` | Cloud default. GHES: `https://HOST/api/v3`. |
| `GHE_ENTERPRISE` | — | Enterprise slug, for enterprise-level audit log / policy. |
| `GHE_MODE` | `read-only` | `read-only` → `read-write` → `admin`. |
| `GHE_ORG_ALLOWLIST` | (all visible) | Comma-separated orgs that may be touched. **Pin this.** |
| `GHE_PROTECTED_ORGS` | — | Orgs readable but never mutated. |
| `GHE_ALLOW_DELETE` | `false` | Required (with admin mode) for any destructive op. |
| `GHE_REQUIRE_CONFIRMATION` | `true` | Destructive ops need a typed confirmation matching the target. |
| `GHE_DRY_RUN` | `false` | Validate + log writes without sending them. |
| `GHE_AUDIT_LOG` | `true` | JSON audit line per op to stderr (also carries the approval receipts). |
| Interactive confirmation | *(automatic)* | — | Destructive & high-impact actions (including org settings, rulesets, branch protection, Actions policy and repo security changes) prompt the human to approve via MCP elicitation before running. The prompt shows the tool, the exact arguments and a fingerprint; the target's version is pinned across the prompt and the action is refused if it changed; a prompt nobody answers is a refusal. `delete_repository` also asks the human to type `org/repo`. |
| `GHE_REQUIRE_HUMAN_APPROVAL` | `false` | When `true`, destructive and high-impact ops are **refused** if the client cannot show an approval prompt (instead of falling back to the `GHE_ALLOW_DELETE` gate alone). |
| `GHE_MAX_PAGES` | `10` | Auto-pagination cap (pages of 100). |
| `GHE_GUARD_MODE` | `off` | Optional laya-guard AI risk gate: `monitor` \| `enforce`. |

See [`.env.example`](.env.example) for the complete list.

## Tools

Registered only up to the active mode: **23** in `read-only`, **32** in `read-write`, **38** in `admin`.

### Read (always on)
`whoami` · `get_rate_limit` · `list_organizations` · `get_organization` · `list_members` · `list_teams` · `list_security_managers` · `list_repositories` · `get_repository` · `get_branch_protection` · `list_org_rulesets` · `list_webhooks` · `get_actions_permissions` · `list_self_hosted_runners` · `list_runner_groups` · `get_actions_cache_usage` · `list_workflows` · `list_secret_scanning_alerts` · `list_code_scanning_alerts` · `list_dependabot_alerts` · `get_audit_log` · **`assess_org_posture`** · **`recommend_enterprise_setup`**

### Write (`read-write`+)
`harden_org_settings` · `update_org_settings` · `set_actions_permissions` · `create_team` · `set_member_role` · `create_org_ruleset` · `protect_branch` · `update_repo_security` · `create_webhook`

Human-approved before they write (when the client can prompt; refused without a prompt under `GHE_REQUIRE_HUMAN_APPROVAL=true`): `harden_org_settings`, `update_org_settings`, `set_actions_permissions`, `create_org_ruleset`, `protect_branch`, `update_repo_security`, `create_webhook`, and `set_member_role` when granting `admin`. The prompt shows what changes (`current → new` per field; for `create_org_ruleset`, the new ruleset next to the existing ones) and the approval is pinned to the state it was shown. Under `GHE_DRY_RUN=true` they return before any prompt. `create_team` is not prompted.

### Admin (`admin`, destructive ones also need `GHE_ALLOW_DELETE`)
`create_repository` (additive, not prompted) · `delete_repository` · `remove_member` · `delete_team` · `delete_org_ruleset` · `delete_webhook`

## Security posture baseline

`assess_org_posture { org }` scores an organization against a built-in baseline and returns per-control findings with a grade:

```jsonc
{
  "org": "acme",
  "summary": { "score": 60, "grade": "C", "passed": 6, "failed": 4, "high_failures": 2 },
  "findings": [
    { "id": "push-protection", "severity": "high", "status": "fail",
      "current": false, "recommended": true,
      "rationale": "Blocks secrets at push time — the only control that prevents the leak…",
      "remediation": "harden_org_settings, or update_org_settings { secret_scanning_push_protection_enabled_for_new_repositories: true }." }
  ]
}
```

Then `harden_org_settings { org }` applies the baseline (base **read** permission, secret scanning + push protection, Dependabot defaults, no public-repo creation, no private forks, commit sign-off) — preview-able with `GHE_DRY_RUN=true`. `recommend_enterprise_setup` returns the full enterprise → org → repo setup template.

> **2FA** is reported by the assessor but must be enforced in the org/enterprise authentication UI — GitHub does not expose it as a REST toggle.

## Skills

Two bundled [Agent Skills](https://modelcontextprotocol.io) in [`.claude/skills`](.claude/skills):

- **`github-enterprise-admin`** — the operator playbook: least-privilege token setup, the secure-setup template, the org-policy baseline, and the guardrails for destructive work.
- **`github-actions-optimization`** — pipeline optimization strategy, a caching strategy (dependencies, Docker layers, cache limits), and **self-hosted runners on Kubernetes** with actions-runner-controller (ARC): GitHub App/PAT connection, autoscaling, caching across ephemeral pods, and runner isolation.

A third, `mcp-suite-maintenance`, documents how to safely extend this server.

## Development

```bash
npm install
npm run typecheck && npm test && npm run build
npm run dev   # watch mode
```

Architecture (shared across the suite): `config.ts` (env → typed config) · `security.ts` (pure policy engine, unit-tested) · `github/client.ts` (REST wrapper) · `baseline.ts` (pure posture assessor) · `tools/{read,write,admin}.ts` (capability-tagged). See [SECURITY.md](SECURITY.md) and [PUBLISHING.md](PUBLISHING.md).

## License

MIT © dockndevai
