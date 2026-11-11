# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/) and the project uses semver.

## [0.2.0] - 2026-11-11

### Security
- **Approval prompts are fully reviewable.** Arguments are shown in full up to 16 000 characters (previously cut at 1500, so a padded prefix could hide the tail of a long statement); a longer action is refused instead of approved blind. Secret redaction in prompts matches whole words (`bypass`/`tokenizer` are no longer shown as `[redacted]`).
- laya-guard now receives the secret-redacted arguments (`canonicalArgs`) instead of `JSON.stringify(args)`, so credentials in tool arguments no longer reach the guard prompt, the guard daemon, or its log.
- **Approval no longer fails open on timeout.** The human-approval prompt used the MCP SDK's default
  60 s request timeout, and a timeout fell through to "approved" (the `GHE_ALLOW_DELETE` gate had already
  passed). A prompt nobody answered therefore auto-approved a destructive operation. A timeout is now a
  refusal, and the wait defaults to 5 minutes.

### Added
- **Approvals are bound to the exact action.** The prompt shows the tool, the full (secret-redacted)
  arguments and a fingerprint; every approval and refusal is written to the audit log as
  `"audit":"approval"` with the fingerprint, resource version and `approvedBy` (`human` / `flag-only`).
  This applies to every confirmation, including the ones laya-guard raises.
- **Approvals are bound to the target's version.** `delete_repository`, `remove_member`, `delete_team`,
  `delete_org_ruleset`, `delete_webhook`, `harden_org_settings`, `set_member_role` (to `admin`) and
  `create_webhook` read a version token before the prompt and again after the human answers, and refuse if it
  changed (see SECURITY.md for what each token covers).
- `GHE_REQUIRE_HUMAN_APPROVAL=true` — refuse destructive / high-impact ops when the client cannot elicit.
- `delete_repository` asks the human to type the repository's `org/repo`.

### Fixed
- The server advertised version `0.1.0` over MCP while the package was `0.1.1`. It now reads its version
  from `package.json` at runtime, and a test fails if the advertised version, `package.json`, `server.json`
  or `package-lock.json` diverge.

Tracking issue: https://github.com/dockndevai/mcp-core/issues/1

## [0.1.1] - 2026-11-06

### Changed
- Republish to escape an npm staging-limbo on the `0.1.0` upload (npm reported
  success but committed only a `0.0.0-stage` placeholder, so the version never
  became installable or registrable). No code changes from `0.1.0`.

## [0.1.0] - 2026-11-06

### Added
- Initial release. MCP stdio server for GitHub Enterprise (Cloud & Server).
- Safe-by-default governance: access modes (read-only → read-write → admin),
  org allowlist, protected orgs, delete gating, typed confirmation, dry-run,
  JSON audit log, optional laya-guard AI risk gate.
- **38 tools** across read / write / admin:
  - Discovery & audit: `whoami`, `get_rate_limit`, `list_organizations`,
    `get_organization`, `list_members`, `list_teams`, `list_security_managers`,
    `list_repositories`, `get_repository`, `get_branch_protection`,
    `list_org_rulesets`, `list_webhooks`, `get_audit_log`.
  - Security posture: `assess_org_posture` (scores an org against the baseline),
    `recommend_enterprise_setup` (staged secure-setup template), security-alert
    listings (secret-scanning values redacted, Dependabot, code-scanning).
  - Actions / CI: `get_actions_permissions`, `list_self_hosted_runners`,
    `list_runner_groups`, `get_actions_cache_usage`, `list_workflows`.
  - Hardening & management (write): `harden_org_settings`, `update_org_settings`,
    `set_actions_permissions`, `create_team`, `set_member_role`,
    `create_org_ruleset`, `protect_branch`, `update_repo_security`,
    `create_webhook`.
  - Admin: `create_repository`, and gated destructive `delete_repository`,
    `remove_member`, `delete_team`, `delete_org_ruleset`, `delete_webhook`.
- Secret redaction for webhook configs and secret-scanning alerts.
- REST client with keyset auto-pagination (Link header) and rate-limit surfacing.
- Bundled skills: `github-enterprise-admin` (setup template + guardrails) and
  `github-actions-optimization` (pipeline optimization, caching, runners on
  Kubernetes via actions-runner-controller).
