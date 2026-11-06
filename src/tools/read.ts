import { z } from "zod";
import type { ToolDef } from "./types.js";
import { jsonResult } from "./types.js";
import { redact, redactSecretScanningAlerts } from "../github/redact.js";
import {
  ENTERPRISE_SETUP_TEMPLATE,
  ORG_SECURITY_BASELINE,
  assessPosture,
  summarize,
  type ActionsPermissions,
  type OrgSettings,
} from "../baseline.js";

/** Every org-scoped tool takes the org login; kept consistent so the model always knows the shape. */
const org = z.string().describe("Organization login (must be within GHE_ORG_ALLOWLIST when that is set)");
const repo = z.string().describe("Repository name (without the org/ prefix)");
const alertState = z.enum(["open", "resolved", "dismissed", "fixed", "auto_dismissed"]).optional();

export const readTools: ToolDef[] = [
  {
    name: "whoami",
    capability: "read",
    config: {
      title: "Who am I",
      description:
        "Return the identity behind the configured GHE_TOKEN (login, type, and whether it is a user or an app). " +
        "Use this first to confirm the token and base URL are wired correctly before anything else.",
      inputSchema: {},
    },
    handler: async (_a, { client, policy }) => {
      policy.guard({ tool: "whoami", capability: "read" });
      return jsonResult(await client.whoami());
    },
  },
  {
    name: "get_rate_limit",
    capability: "read",
    config: {
      title: "Get API rate limit",
      description: "Report the current REST API rate-limit budget (core, search, graphql) and reset times. Use to pace bulk reads.",
      inputSchema: {},
    },
    handler: async (_a, { client, policy }) => {
      policy.guard({ tool: "get_rate_limit", capability: "read" });
      return jsonResult(await client.rateLimit());
    },
  },
  {
    name: "list_organizations",
    capability: "read",
    config: {
      title: "List organizations",
      description:
        "List the organizations the token can see (filtered by GHE_ORG_ALLOWLIST), each flagged if it is protected " +
        "(readable but never mutated). Start here to discover valid org logins.",
      inputSchema: {},
    },
    handler: async (_a, { client, policy }) => {
      policy.guard({ tool: "list_organizations", capability: "read" });
      const orgs = (await client.listOrgs()) as Array<{ login: string; id: number; description?: string }>;
      return jsonResult(
        orgs
          .filter((o) => policy.isOrgAllowed(o.login))
          .map((o) => ({ login: o.login, id: o.id, description: o.description ?? null, protected: policy.isOrgProtected(o.login) })),
      );
    },
  },
  {
    name: "get_organization",
    capability: "read",
    config: {
      title: "Get organization",
      description: "Fetch an organization's full profile and security-relevant settings (2FA, base permission, secret scanning & Dependabot defaults).",
      inputSchema: { org },
    },
    handler: async (a, { client, policy }) => {
      const o = a.org as string;
      policy.guard({ tool: "get_organization", capability: "read", org: o });
      return jsonResult(await client.getOrg(o));
    },
  },
  {
    name: "list_members",
    capability: "read",
    config: {
      title: "List organization members",
      description: "List an organization's members, optionally filtered by role (admin = owners, member = everyone else).",
      inputSchema: { org, role: z.enum(["all", "admin", "member"]).optional().describe("Filter by role; default all") },
    },
    handler: async (a, { client, policy }) => {
      const o = a.org as string;
      policy.guard({ tool: "list_members", capability: "read", org: o });
      const role = (a.role as string) ?? "all";
      return jsonResult(await client.listMembers(o, role === "all" ? undefined : role));
    },
  },
  {
    name: "list_teams",
    capability: "read",
    config: {
      title: "List teams",
      description: "List an organization's teams with their slugs, privacy, and permissions. Use a team slug with the team tools.",
      inputSchema: { org },
    },
    handler: async (a, { client, policy }) => {
      const o = a.org as string;
      policy.guard({ tool: "list_teams", capability: "read", org: o });
      return jsonResult(await client.listTeams(o));
    },
  },
  {
    name: "list_security_managers",
    capability: "read",
    config: {
      title: "List security managers",
      description: "List the teams granted the organization's security-manager role (least-privilege security triage).",
      inputSchema: { org },
    },
    handler: async (a, { client, policy }) => {
      const o = a.org as string;
      policy.guard({ tool: "list_security_managers", capability: "read", org: o });
      return jsonResult(await client.listSecurityManagers(o));
    },
  },
  {
    name: "list_repositories",
    capability: "read",
    config: {
      title: "List repositories",
      description: "List an organization's repositories (name, visibility, default branch, archived), optionally filtered by type.",
      inputSchema: {
        org,
        type: z.enum(["all", "public", "private", "forks", "sources", "member"]).optional().describe("Filter by type; default all"),
      },
    },
    handler: async (a, { client, policy }) => {
      const o = a.org as string;
      policy.guard({ tool: "list_repositories", capability: "read", org: o });
      return jsonResult(await client.listRepos(o, a.type as string | undefined));
    },
  },
  {
    name: "get_repository",
    capability: "read",
    config: {
      title: "Get repository",
      description: "Fetch a single repository including its security_and_analysis settings (secret scanning, push protection, advanced security).",
      inputSchema: { org, repo },
    },
    handler: async (a, { client, policy }) => {
      const o = a.org as string;
      policy.guard({ tool: "get_repository", capability: "read", org: o });
      return jsonResult(await client.getRepo(o, a.repo as string));
    },
  },
  {
    name: "get_branch_protection",
    capability: "read",
    config: {
      title: "Get branch protection",
      description: "Fetch the protection settings for a branch (required reviews, status checks, signatures, force-push rules).",
      inputSchema: { org, repo, branch: z.string().describe("Branch name, e.g. main") },
    },
    handler: async (a, { client, policy }) => {
      const o = a.org as string;
      policy.guard({ tool: "get_branch_protection", capability: "read", org: o });
      return jsonResult(await client.getBranchProtection(o, a.repo as string, a.branch as string));
    },
  },
  {
    name: "list_org_rulesets",
    capability: "read",
    config: {
      title: "List organization rulesets",
      description: "List the organization's rulesets (the modern, org-wide replacement for per-repo branch protection).",
      inputSchema: { org },
    },
    handler: async (a, { client, policy }) => {
      const o = a.org as string;
      policy.guard({ tool: "list_org_rulesets", capability: "read", org: o });
      return jsonResult(await client.listOrgRulesets(o));
    },
  },
  {
    name: "list_webhooks",
    capability: "read",
    config: {
      title: "List organization webhooks",
      description: "List the organization's webhooks and their events. Webhook secrets are redacted and never returned.",
      inputSchema: { org },
    },
    handler: async (a, { client, policy }) => {
      const o = a.org as string;
      policy.guard({ tool: "list_webhooks", capability: "read", org: o });
      return jsonResult(redact(await client.listWebhooks(o)));
    },
  },
  {
    name: "get_actions_permissions",
    capability: "read",
    config: {
      title: "Get Actions permissions",
      description: "Fetch the organization's GitHub Actions policy (which repos may run Actions, and which actions are allowed).",
      inputSchema: { org },
    },
    handler: async (a, { client, policy }) => {
      const o = a.org as string;
      policy.guard({ tool: "get_actions_permissions", capability: "read", org: o });
      return jsonResult(await client.getActionsPermissions(o));
    },
  },
  {
    name: "list_self_hosted_runners",
    capability: "read",
    config: {
      title: "List self-hosted runners",
      description:
        "List the organization's self-hosted Actions runners (name, status, labels, busy). Use with runner groups to audit " +
        "where CI executes — e.g. Kubernetes runners managed by actions-runner-controller.",
      inputSchema: { org },
    },
    handler: async (a, { client, policy }) => {
      const o = a.org as string;
      policy.guard({ tool: "list_self_hosted_runners", capability: "read", org: o });
      return jsonResult(await client.listSelfHostedRunners(o));
    },
  },
  {
    name: "list_runner_groups",
    capability: "read",
    config: {
      title: "List runner groups",
      description: "List the organization's self-hosted runner groups and which repositories may use them (runner isolation).",
      inputSchema: { org },
    },
    handler: async (a, { client, policy }) => {
      const o = a.org as string;
      policy.guard({ tool: "list_runner_groups", capability: "read", org: o });
      return jsonResult(await client.listRunnerGroups(o));
    },
  },
  {
    name: "get_actions_cache_usage",
    capability: "read",
    config: {
      title: "Get Actions cache usage",
      description:
        "Report GitHub Actions cache usage — org-wide, or for one repository. Use to spot caches near the 10 GB/repo limit " +
        "and to size a caching strategy for faster pipelines.",
      inputSchema: { org, repo: z.string().optional().describe("Optional: a single repo. Omit for org-wide totals.") },
    },
    handler: async (a, { client, policy }) => {
      const o = a.org as string;
      policy.guard({ tool: "get_actions_cache_usage", capability: "read", org: o });
      return jsonResult(a.repo ? await client.getRepoCacheUsage(o, a.repo as string) : await client.getOrgCacheUsage(o));
    },
  },
  {
    name: "list_workflows",
    capability: "read",
    config: {
      title: "List workflows",
      description: "List the Actions workflows defined in a repository (name, path, state). Starting point for pipeline optimization.",
      inputSchema: { org, repo },
    },
    handler: async (a, { client, policy }) => {
      const o = a.org as string;
      policy.guard({ tool: "list_workflows", capability: "read", org: o });
      return jsonResult(await client.listWorkflows(o, a.repo as string));
    },
  },
  {
    name: "list_secret_scanning_alerts",
    capability: "read",
    config: {
      title: "List secret-scanning alerts",
      description:
        "List the organization's secret-scanning alerts (type, state, repo, location). The matched secret value itself is " +
        "dropped and never returned.",
      inputSchema: { org, state: alertState },
    },
    handler: async (a, { client, policy }) => {
      const o = a.org as string;
      policy.guard({ tool: "list_secret_scanning_alerts", capability: "read", org: o });
      return jsonResult(redactSecretScanningAlerts(await client.listSecretScanningAlerts(o, a.state as string | undefined)));
    },
  },
  {
    name: "list_code_scanning_alerts",
    capability: "read",
    config: {
      title: "List code-scanning alerts",
      description: "List the organization's code-scanning (CodeQL/SARIF) alerts with rule, severity, state, and location.",
      inputSchema: { org, state: alertState },
    },
    handler: async (a, { client, policy }) => {
      const o = a.org as string;
      policy.guard({ tool: "list_code_scanning_alerts", capability: "read", org: o });
      return jsonResult(redact(await client.listCodeScanningAlerts(o, a.state as string | undefined)));
    },
  },
  {
    name: "list_dependabot_alerts",
    capability: "read",
    config: {
      title: "List Dependabot alerts",
      description: "List the organization's Dependabot (vulnerable dependency) alerts with package, severity, state, and the fixing version.",
      inputSchema: { org, state: alertState },
    },
    handler: async (a, { client, policy }) => {
      const o = a.org as string;
      policy.guard({ tool: "list_dependabot_alerts", capability: "read", org: o });
      return jsonResult(redact(await client.listDependabotAlerts(o, a.state as string | undefined)));
    },
  },
  {
    name: "get_audit_log",
    capability: "read",
    config: {
      title: "Get audit log",
      description:
        "Fetch recent audit-log events for the organization (or the enterprise, when GHE_ENTERPRISE is set), optionally " +
        "filtered by a search phrase like 'action:repo.destroy' or 'actor:octocat'.",
      inputSchema: {
        org,
        scope: z.enum(["org", "enterprise"]).optional().describe("Default org. 'enterprise' requires GHE_ENTERPRISE."),
        phrase: z.string().optional().describe("Audit-log search phrase, e.g. action:org.update_member"),
        perPage: z.number().int().min(1).max(100).optional().describe("Events to return (1–100, default 50)"),
      },
    },
    handler: async (a, { client, policy }) => {
      const o = a.org as string;
      policy.guard({ tool: "get_audit_log", capability: "read", org: o });
      const perPage = (a.perPage as number) ?? 50;
      if ((a.scope as string) === "enterprise") {
        const ent = process.env.GHE_ENTERPRISE?.trim();
        if (!ent) return { content: [{ type: "text" as const, text: "GHE_ENTERPRISE is not set; cannot query the enterprise audit log." }], isError: true };
        return jsonResult(redact(await client.enterpriseAuditLog(ent, a.phrase as string | undefined, perPage)));
      }
      return jsonResult(redact(await client.orgAuditLog(o, a.phrase as string | undefined, perPage)));
    },
  },
  {
    name: "assess_org_posture",
    capability: "read",
    config: {
      title: "Assess org security posture",
      description:
        "Score an organization against the built-in security baseline (2FA, base permission, secret scanning + push " +
        "protection, Dependabot, Actions policy). Returns per-control findings (pass/fail/unknown with severity and the exact " +
        "remediation tool) plus a summary grade. Read-only — it changes nothing; apply fixes with harden_org_settings.",
      inputSchema: { org },
    },
    handler: async (a, { client, policy }) => {
      const o = a.org as string;
      policy.guard({ tool: "assess_org_posture", capability: "read", org: o });
      const settings = (await client.getOrg(o)) as OrgSettings;
      let actions: ActionsPermissions | undefined;
      try {
        actions = (await client.getActionsPermissions(o)) as ActionsPermissions;
      } catch {
        actions = undefined; // token may lack the Actions scope; posture still scores the org settings.
      }
      const findings = assessPosture(settings, actions);
      return jsonResult({ org: o, summary: summarize(findings), findings });
    },
  },
  {
    name: "recommend_enterprise_setup",
    capability: "read",
    config: {
      title: "Recommend enterprise setup",
      description:
        "Return the staged secure-setup template for a GitHub Enterprise — enterprise, organization, and repository level " +
        "controls with the rationale for each, plus the exact org-settings baseline that harden_org_settings applies. " +
        "Pure guidance; use assess_org_posture to measure a specific org against it.",
      inputSchema: {},
    },
    handler: async (_a, { policy }) => {
      policy.guard({ tool: "recommend_enterprise_setup", capability: "read" });
      return jsonResult({ template: ENTERPRISE_SETUP_TEMPLATE, org_settings_baseline: ORG_SECURITY_BASELINE });
    },
  },
];
