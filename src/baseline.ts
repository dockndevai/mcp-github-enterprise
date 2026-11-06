/**
 * Org security-posture baseline — the "secure by default" template for a
 * GitHub Enterprise organization, plus a pure assessor that scores a live org
 * against it. No I/O: `assessPosture()` takes the JSON GitHub already returned
 * (GET /orgs/{org} and GET /orgs/{org}/actions/permissions) and emits findings.
 *
 * Each check maps to a concrete, writable org setting, so a finding can name the
 * exact tool + field that remediates it. Severities follow the blast radius if
 * the control is missing.
 */

export type Severity = "high" | "medium" | "low";
export type Status = "pass" | "fail" | "unknown";

export interface Finding {
  id: string;
  title: string;
  severity: Severity;
  status: Status;
  current: unknown;
  recommended: unknown;
  rationale: string;
  /** How to fix it with this server's tools. */
  remediation: string;
}

export interface OrgSettings {
  // GET /orgs/{org}
  two_factor_requirement_enabled?: boolean | null;
  default_repository_permission?: string | null;
  members_can_create_repositories?: boolean | null;
  members_can_create_public_repositories?: boolean | null;
  members_can_fork_private_repositories?: boolean | null;
  web_commit_signoff_required?: boolean | null;
  secret_scanning_enabled_for_new_repositories?: boolean | null;
  secret_scanning_push_protection_enabled_for_new_repositories?: boolean | null;
  dependabot_alerts_enabled_for_new_repositories?: boolean | null;
  dependabot_security_updates_enabled_for_new_repositories?: boolean | null;
  dependency_graph_enabled_for_new_repositories?: boolean | null;
  [k: string]: unknown;
}

export interface ActionsPermissions {
  // GET /orgs/{org}/actions/permissions
  enabled_repositories?: string | null; // all | none | selected
  allowed_actions?: string | null; // all | local_only | selected
  [k: string]: unknown;
}

/** The recommended target settings — the body `harden_org_settings` applies. */
export const ORG_SECURITY_BASELINE: Record<string, unknown> = {
  default_repository_permission: "read",
  members_can_create_public_repositories: false,
  members_can_fork_private_repositories: false,
  web_commit_signoff_required: true,
  secret_scanning_enabled_for_new_repositories: true,
  secret_scanning_push_protection_enabled_for_new_repositories: true,
  dependabot_alerts_enabled_for_new_repositories: true,
  dependabot_security_updates_enabled_for_new_repositories: true,
  dependency_graph_enabled_for_new_repositories: true,
};

function check(
  id: string,
  title: string,
  severity: Severity,
  current: unknown,
  ok: boolean,
  recommended: unknown,
  rationale: string,
  remediation: string,
): Finding {
  return {
    id,
    title,
    severity,
    status: current === undefined || current === null ? "unknown" : ok ? "pass" : "fail",
    current: current ?? null,
    recommended,
    rationale,
    remediation,
  };
}

export function assessPosture(org: OrgSettings, actions?: ActionsPermissions): Finding[] {
  const f: Finding[] = [];

  f.push(
    check(
      "two-factor",
      "Require two-factor authentication for all members",
      "high",
      org.two_factor_requirement_enabled,
      org.two_factor_requirement_enabled === true,
      true,
      "Without org-enforced 2FA a single phished password compromises the org. 2FA is the highest-leverage control.",
      "Enforce in the org/enterprise authentication settings (GitHub requires the UI/SSO for the actual toggle).",
    ),
  );
  f.push(
    check(
      "default-permission",
      "Base repository permission is read (not write/admin)",
      "medium",
      org.default_repository_permission,
      org.default_repository_permission === "read" || org.default_repository_permission === "none",
      "read",
      "A write/admin base permission grants every member standing access to every repo — the opposite of least privilege.",
      "harden_org_settings, or update_org_settings { default_repository_permission: 'read' }.",
    ),
  );
  f.push(
    check(
      "public-repos",
      "Members cannot create public repositories",
      "medium",
      org.members_can_create_public_repositories,
      org.members_can_create_public_repositories === false,
      false,
      "Unrestricted public-repo creation is a common source of accidental source/secret exposure.",
      "harden_org_settings, or update_org_settings { members_can_create_public_repositories: false }.",
    ),
  );
  f.push(
    check(
      "private-fork",
      "Forking of private repositories is disabled",
      "medium",
      org.members_can_fork_private_repositories,
      org.members_can_fork_private_repositories === false,
      false,
      "Private forks multiply the copies of sensitive code and escape repo-level controls.",
      "harden_org_settings, or update_org_settings { members_can_fork_private_repositories: false }.",
    ),
  );
  f.push(
    check(
      "secret-scanning",
      "Secret scanning enabled for new repositories",
      "high",
      org.secret_scanning_enabled_for_new_repositories,
      org.secret_scanning_enabled_for_new_repositories === true,
      true,
      "Catches committed credentials automatically instead of after a breach.",
      "harden_org_settings, or update_org_settings { secret_scanning_enabled_for_new_repositories: true }.",
    ),
  );
  f.push(
    check(
      "push-protection",
      "Secret scanning push protection enabled for new repositories",
      "high",
      org.secret_scanning_push_protection_enabled_for_new_repositories,
      org.secret_scanning_push_protection_enabled_for_new_repositories === true,
      true,
      "Blocks secrets at push time — the only control that prevents the leak rather than reporting it.",
      "harden_org_settings, or update_org_settings { secret_scanning_push_protection_enabled_for_new_repositories: true }.",
    ),
  );
  f.push(
    check(
      "dependabot-alerts",
      "Dependabot alerts enabled for new repositories",
      "medium",
      org.dependabot_alerts_enabled_for_new_repositories,
      org.dependabot_alerts_enabled_for_new_repositories === true,
      true,
      "Surfaces known-vulnerable dependencies across the org without per-repo opt-in.",
      "harden_org_settings, or update_org_settings { dependabot_alerts_enabled_for_new_repositories: true }.",
    ),
  );
  f.push(
    check(
      "dependabot-updates",
      "Dependabot security updates enabled for new repositories",
      "low",
      org.dependabot_security_updates_enabled_for_new_repositories,
      org.dependabot_security_updates_enabled_for_new_repositories === true,
      true,
      "Automated fix PRs shrink the window between disclosure and patch.",
      "harden_org_settings, or update_org_settings { dependabot_security_updates_enabled_for_new_repositories: true }.",
    ),
  );
  f.push(
    check(
      "dependency-graph",
      "Dependency graph enabled for new repositories",
      "low",
      org.dependency_graph_enabled_for_new_repositories,
      org.dependency_graph_enabled_for_new_repositories === true,
      true,
      "The dependency graph is the prerequisite for Dependabot and supply-chain visibility.",
      "harden_org_settings, or update_org_settings { dependency_graph_enabled_for_new_repositories: true }.",
    ),
  );
  f.push(
    check(
      "commit-signoff",
      "Require commit sign-off on web commits",
      "low",
      org.web_commit_signoff_required,
      org.web_commit_signoff_required === true,
      true,
      "Establishes a clear authorship/DCO trail for contributions made through the web UI.",
      "harden_org_settings, or update_org_settings { web_commit_signoff_required: true }.",
    ),
  );

  if (actions) {
    f.push(
      check(
        "actions-allowed",
        "Allowed GitHub Actions restricted (not 'all')",
        "medium",
        actions.allowed_actions,
        actions.allowed_actions === "selected" || actions.allowed_actions === "local_only",
        "selected",
        "Allowing any action from the marketplace pulls untrusted third-party code into CI. Pin to local or vetted actions.",
        "set_actions_permissions { allowed_actions: 'selected' } (then configure the allow list).",
      ),
    );
    f.push(
      check(
        "actions-enabled-repos",
        "Actions enabled only for selected repositories",
        "low",
        actions.enabled_repositories,
        actions.enabled_repositories === "selected" || actions.enabled_repositories === "none",
        "selected",
        "Scoping which repos may run Actions limits where self-hosted runners and org secrets are reachable.",
        "set_actions_permissions { enabled_repositories: 'selected' }.",
      ),
    );
  }

  return f;
}

/** A compact score so a model/operator can see posture at a glance. */
export function summarize(findings: Finding[]): {
  score: number;
  grade: string;
  passed: number;
  failed: number;
  unknown: number;
  high_failures: number;
} {
  const scored = findings.filter((x) => x.status !== "unknown");
  const passed = scored.filter((x) => x.status === "pass").length;
  const failed = scored.filter((x) => x.status === "fail").length;
  const unknown = findings.length - scored.length;
  const score = scored.length ? Math.round((passed / scored.length) * 100) : 0;
  const grade = score >= 90 ? "A" : score >= 75 ? "B" : score >= 60 ? "C" : score >= 40 ? "D" : "F";
  return { score, grade, passed, failed, unknown, high_failures: findings.filter((x) => x.severity === "high" && x.status === "fail").length };
}

/**
 * The enterprise setup template — the staged checklist `recommend_enterprise_setup`
 * returns. Structured data, not prose, so a client can render or act on it.
 */
export const ENTERPRISE_SETUP_TEMPLATE = {
  enterprise: [
    { item: "Enforce SSO/SAML (and SCIM provisioning) for the enterprise", why: "Central identity, instant deprovisioning, MFA at the IdP." },
    { item: "Require two-factor authentication at the enterprise policy level", why: "Covers every org; members cannot opt out." },
    { item: "Configure an IP allow list (and enable for installed GitHub Apps)", why: "Limits where the enterprise can be reached from." },
    { item: "Set the enterprise Actions policy (allowed actions, fork-PR approval, token default = read)", why: "Controls untrusted CI code and token blast radius org-wide." },
    { item: "Restrict repository creation & visibility change policies", why: "Prevents accidental public exposure of internal code." },
    { item: "Stream the enterprise audit log + git events to your SIEM", why: "Tamper-evident record for detection and forensics." },
  ],
  organization: [
    { item: "Apply the org security baseline (assess_org_posture → harden_org_settings)", why: "2FA, base read permission, secret scanning + push protection, Dependabot." },
    { item: "Assign security managers (least-privilege security role)", why: "Security team can triage alerts without org-owner rights." },
    { item: "Define org rulesets (require PR review, signed commits, block force-push on default branches)", why: "Consistent branch protection across all repos." },
    { item: "Pin allowed Actions and runner groups; avoid default self-hosted runners on public repos", why: "Supply-chain and runner-isolation hygiene." },
    { item: "Turn on secret scanning, push protection, Dependabot & code scanning defaults for new repos", why: "Security on by default, not per-repo opt-in." },
  ],
  repository: [
    { item: "Protect default + release branches with a ruleset (reviews, status checks, linear history)", why: "No unreviewed or force-pushed changes to protected branches." },
    { item: "Enable code scanning (CodeQL default setup) and Dependabot security updates", why: "Static analysis + automated dependency patching." },
    { item: "Store CI credentials as encrypted secrets / OIDC, never in the repo", why: "Short-lived, least-privilege CI identity." },
  ],
} as const;
