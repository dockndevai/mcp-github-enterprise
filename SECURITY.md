# Security & governance

`mcp-github-enterprise` exposes GitHub Enterprise administration to an AI agent.
Treat it like any other privileged automation and grant it the least access it needs.

## Governance controls

- **Start read-only.** Leave `GHE_MODE=read-only` until you need changes. Tools
  above the current mode are never registered (write/admin tools are not even
  advertised).
- **Scope with the token, then with flags.** The token's own scopes are the
  primary control — use a least-privilege fine-grained PAT or GitHub App
  installation token, read-only to begin. `GHE_ORG_ALLOWLIST` further limits which
  organizations are reachable, and `GHE_PROTECTED_ORGS` marks orgs that can be read
  but never mutated (read-only forever, regardless of mode).
- **Gate destructive ops explicitly.** `delete_repository`, `remove_member`,
  `delete_team`, `delete_org_ruleset`, and `delete_webhook` each require `admin`
  mode **and** `GHE_ALLOW_DELETE=true`.
- **Typed confirmation for high-impact ops.** With `GHE_REQUIRE_CONFIRMATION=true`
  (default), each destructive op also requires a `confirm` argument that exactly
  equals the target (`org/repo`, the username, the team slug, or the id) — a
  boolean is not enough. This prevents an agent from deleting the wrong thing on a
  loose instruction. When the client supports MCP elicitation, a human is also
  prompted to approve.
- **Preview with dry-run.** `GHE_DRY_RUN=true` validates and logs write intent
  without calling GitHub.
- **Keep the audit log on.** `GHE_AUDIT_LOG=true` (default) writes a JSON line per
  guarded operation to stderr — ship it to your SIEM.
- **Optional AI risk gate.** `GHE_GUARD_MODE=monitor|enforce` routes mutating ops
  through a local laya-guard daemon that can only *tighten* (add a confirmation or
  block); it fails closed.

## Handling of credentials & secrets

- The token is read from the environment and sent only as the bearer auth header
  to the configured API host; it is never logged or returned in tool results.
- Responses are redacted before they reach the model: webhook
  `config.secret`/`token`/`password` are masked, and secret-scanning alert
  `secret` values are dropped entirely. When you create a webhook, its signing
  secret is write-only — sent to GitHub, never echoed back.

## Least-privilege token scopes

- **Read/audit:** org `members:read`, `administration:read`; repo `metadata:read`;
  `secret_scanning_alerts:read`, Dependabot/code-scanning `:read`.
- **Hardening:** add org `administration:write` and repo `administration:write`.
- **Enterprise audit log:** a classic PAT with `read:audit_log` plus `GHE_ENTERPRISE`.

## Reporting a vulnerability

Please open a private security advisory on the GitHub repository rather than a
public issue.
