# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/) and the project uses semver.

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
