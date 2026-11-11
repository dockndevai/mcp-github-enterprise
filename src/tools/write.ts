import { z } from "zod";
import type { ToolDef } from "./types.js";
import { jsonResult, textResult } from "./types.js";
import { ORG_SECURITY_BASELINE } from "../baseline.js";
import { redact } from "../github/redact.js";
import { change, pinned, show } from "./changes.js";

const org = z.string().describe("Organization login (must be within GHE_ORG_ALLOWLIST when that is set)");
const repo = z.string().describe("Repository name (without the org/ prefix)");

/** Only these org fields may be written — an allowlist so a typo or an injected key can't flip an unrelated setting. */
const WRITABLE_ORG_KEYS = new Set([
  "default_repository_permission",
  "members_can_create_repositories",
  "members_can_create_public_repositories",
  "members_can_create_private_repositories",
  "members_can_fork_private_repositories",
  "web_commit_signoff_required",
  "secret_scanning_enabled_for_new_repositories",
  "secret_scanning_push_protection_enabled_for_new_repositories",
  "dependabot_alerts_enabled_for_new_repositories",
  "dependabot_security_updates_enabled_for_new_repositories",
  "dependency_graph_enabled_for_new_repositories",
  "advanced_security_enabled_for_new_repositories",
]);

/** One `current → new` line per org field about to be written; unwritable keys the caller passed are listed too. */
function orgChangeDetails(
  snap: { current: Record<string, unknown> } | undefined,
  body: Record<string, unknown>,
  ignored: string[] = [],
): Record<string, string> {
  const details: Record<string, string> = {};
  for (const k of Object.keys(body)) details[k] = snap ? change(snap.current[k], body[k]) : `(current value unavailable) → ${show(body[k])}`;
  if (ignored.length) details["ignored (not writable)"] = ignored.join(", ");
  return details;
}

export const writeTools: ToolDef[] = [
  {
    name: "harden_org_settings",
    capability: "write",
    config: {
      title: "Harden org settings (apply baseline)",
      description:
        "Apply the recommended org security baseline in one call: base read permission, no public-repo creation, no " +
        "private forks, secret scanning + push protection and Dependabot defaults for new repos, and web commit sign-off. " +
        "Preview with assess_org_posture first. Honors dry-run and asks for confirmation before it writes.",
      inputSchema: {
        org,
        overrides: z
          .record(z.string(), z.any())
          .optional()
          .describe("Optional per-field overrides of the baseline, e.g. { web_commit_signoff_required: false }"),
      },
    },
    handler: async (a, { client, policy, confirm }) => {
      const o = a.org as string;
      const { dryRun } = policy.guard({ tool: "harden_org_settings", capability: "write", org: o });
      const body: Record<string, unknown> = { ...ORG_SECURITY_BASELINE };
      const ignored: string[] = [];
      for (const [k, v] of Object.entries((a.overrides as Record<string, unknown>) ?? {})) {
        if (WRITABLE_ORG_KEYS.has(k)) body[k] = v;
        else ignored.push(k);
      }
      if (dryRun) return textResult(`[dry-run] Would PATCH org '${o}' settings: ${JSON.stringify(body)}`);
      const keys = Object.keys(body);
      const snap = await client.orgSettingsSnapshot(o, keys);
      const ok = await confirm.confirm({
        action: "apply the security baseline to org settings",
        reversible: true,
        target: o,
        details: orgChangeDetails(snap, body, ignored),
        probe: pinned(snap?.version, () => client.orgSettingsVersion(o, keys)),
      });
      if (!ok.approved) return textResult(`Cancelled — ${ok.reason}.`);
      return jsonResult(await client.updateOrg(o, body));
    },
  },
  {
    name: "update_org_settings",
    capability: "write",
    config: {
      title: "Update org settings",
      description:
        "Update specific organization settings. Only known security/permission fields are accepted (others are ignored). " +
        "Use harden_org_settings to apply the full baseline at once. Honors dry-run and asks a human to approve the " +
        "change (current → new values) before it writes.",
      inputSchema: {
        org,
        settings: z.record(z.string(), z.any()).describe("Map of allowed org fields to set, e.g. { default_repository_permission: 'read' }"),
      },
    },
    handler: async (a, { client, policy, confirm }) => {
      const o = a.org as string;
      const { dryRun } = policy.guard({ tool: "update_org_settings", capability: "write", org: o });
      const body: Record<string, unknown> = {};
      const ignored: string[] = [];
      for (const [k, v] of Object.entries((a.settings as Record<string, unknown>) ?? {})) {
        if (WRITABLE_ORG_KEYS.has(k)) body[k] = v;
        else ignored.push(k);
      }
      if (Object.keys(body).length === 0)
        return { content: [{ type: "text" as const, text: `No writable fields. Allowed: ${[...WRITABLE_ORG_KEYS].join(", ")}` }], isError: true };
      if (dryRun) return textResult(`[dry-run] Would PATCH org '${o}': ${JSON.stringify(body)}${ignored.length ? ` (ignored: ${ignored.join(", ")})` : ""}`);
      const keys = Object.keys(body);
      const snap = await client.orgSettingsSnapshot(o, keys);
      const ok = await confirm.confirm({
        action: "change organization settings",
        reversible: true,
        target: o,
        details: orgChangeDetails(snap, body, ignored),
        probe: pinned(snap?.version, () => client.orgSettingsVersion(o, keys)),
      });
      if (!ok.approved) return textResult(`Cancelled — ${ok.reason}.`);
      return jsonResult(await client.updateOrg(o, body));
    },
  },
  {
    name: "set_actions_permissions",
    capability: "write",
    config: {
      title: "Set Actions permissions",
      description:
        "Set the organization's GitHub Actions policy — which repositories may run Actions and which actions are allowed " +
        "(restrict to 'selected' or 'local_only' to keep untrusted marketplace actions out of CI). Honors dry-run and " +
        "asks a human to approve the change (current → new) before it writes. GitHub requires enabled_repositories on every " +
        "write, so when you set only allowed_actions the current enabled_repositories value is kept.",
      inputSchema: {
        org,
        enabled_repositories: z.enum(["all", "none", "selected"]).optional().describe("Which repos may run Actions"),
        allowed_actions: z.enum(["all", "local_only", "selected"]).optional().describe("Which actions are allowed to run"),
      },
    },
    handler: async (a, { client, policy, confirm }) => {
      const o = a.org as string;
      const { dryRun } = policy.guard({ tool: "set_actions_permissions", capability: "write", org: o });
      const asked: Record<string, unknown> = {};
      if (a.enabled_repositories) asked.enabled_repositories = a.enabled_repositories;
      if (a.allowed_actions) asked.allowed_actions = a.allowed_actions;
      if (Object.keys(asked).length === 0) return { content: [{ type: "text" as const, text: "Nothing to set." }], isError: true };
      if (dryRun) {
        return textResult(
          `[dry-run] Would set Actions permissions on '${o}': ${JSON.stringify(asked)}` +
            (asked.enabled_repositories ? "" : " (enabled_repositories, which GitHub requires, would be kept at its current value)"),
        );
      }
      const snap = await client.actionsPermissionsSnapshot(o);
      // GitHub's PUT /orgs/{org}/actions/permissions requires `enabled_repositories`. Read-modify-write: a field the
      // caller did not name keeps its current value, so setting only `allowed_actions` is a valid request.
      const body: Record<string, unknown> = { ...asked };
      if (body.enabled_repositories === undefined) {
        const cur = snap?.current.enabled_repositories;
        if (typeof cur !== "string") {
          return {
            content: [
              {
                type: "text" as const,
                text:
                  "enabled_repositories is required by GitHub and the org's current Actions policy could not be read; " +
                  "pass enabled_repositories explicitly.",
              },
            ],
            isError: true,
          };
        }
        body.enabled_repositories = cur;
      }
      // Sent back unchanged so the write does not depend on how GitHub treats an omitted `sha_pinning_required`.
      if (snap && snap.current.sha_pinning_required !== undefined) body.sha_pinning_required = snap.current.sha_pinning_required;
      const details: Record<string, string> = {};
      for (const k of ["enabled_repositories", "allowed_actions"] as const) {
        details[k] = !snap ? `(current value unavailable) → ${show(body[k])}` : k in asked ? change(snap.current[k], body[k]) : `${show(snap.current[k])} (unchanged)`;
      }
      if (snap && snap.current.sha_pinning_required !== undefined) details.sha_pinning_required = `${show(snap.current.sha_pinning_required)} (unchanged)`;
      const ok = await confirm.confirm({
        action: "change the organization's GitHub Actions policy",
        reversible: true,
        target: o,
        details,
        probe: pinned(snap?.version, async () => (await client.actionsPermissionsSnapshot(o))?.version),
      });
      if (!ok.approved) return textResult(`Cancelled — ${ok.reason}.`);
      await client.setActionsPermissions(o, body);
      return jsonResult({ updated: true, org: o, ...body });
    },
  },
  {
    name: "create_team",
    capability: "write",
    config: {
      title: "Create team",
      description: "Create a team in an organization with a name, optional description, and privacy (closed/secret).",
      inputSchema: {
        org,
        name: z.string().describe("Team name"),
        description: z.string().optional(),
        privacy: z.enum(["secret", "closed"]).optional().describe("Default closed (visible to all members)"),
      },
    },
    handler: async (a, { client, policy }) => {
      const o = a.org as string;
      const { dryRun } = policy.guard({ tool: "create_team", capability: "write", org: o });
      const body = { name: a.name, description: a.description, privacy: (a.privacy as string) ?? "closed" };
      if (dryRun) return textResult(`[dry-run] Would create team '${a.name}' in '${o}'.`);
      return jsonResult(await client.createTeam(o, body));
    },
  },
  {
    name: "set_member_role",
    capability: "write",
    config: {
      title: "Set member role",
      description: "Set a user's organization membership role (admin = owner, member). Also invites the user if not yet a member.",
      inputSchema: {
        org,
        username: z.string().describe("GitHub login of the user"),
        role: z.enum(["admin", "member"]).describe("admin = org owner; member = regular member"),
      },
    },
    handler: async (a, { client, policy, confirm }) => {
      const o = a.org as string;
      const { dryRun } = policy.guard({ tool: "set_member_role", capability: "write", org: o });
      if (dryRun) return textResult(`[dry-run] Would set ${a.username} to '${a.role}' in '${o}'.`);
      if ((a.role as string) === "admin") {
        const ok = await confirm.confirm({
          action: "grant organization OWNER (admin)",
          target: `${a.username} in ${o}`,
          probe: () => client.membershipVersion(o, a.username as string),
        });
        if (!ok.approved) return textResult(`Cancelled — ${ok.reason}.`);
      }
      return jsonResult(await client.setMembership(o, a.username as string, a.role as string));
    },
  },
  {
    name: "create_org_ruleset",
    capability: "write",
    config: {
      title: "Create organization ruleset",
      description:
        "Create an org-wide ruleset (branch/tag protection). Pass the GitHub ruleset JSON (name, target, enforcement, " +
        "conditions, rules). Example rules: pull_request (required reviews), required_status_checks, non_fast_forward. " +
        "Honors dry-run and asks a human to approve it (shown next to the rulesets already in place) before it creates.",
      inputSchema: {
        org,
        ruleset: z.record(z.string(), z.any()).describe("A GitHub ruleset object. See docs.github.com/rest/orgs/rules."),
      },
    },
    handler: async (a, { client, policy, confirm }) => {
      const o = a.org as string;
      const { dryRun } = policy.guard({ tool: "create_org_ruleset", capability: "write", org: o });
      const body = a.ruleset as Record<string, unknown>;
      if (dryRun) return textResult(`[dry-run] Would create ruleset '${body.name ?? "(unnamed)"}' in '${o}'.`);
      const snap = await client.rulesetSetSnapshot(o);
      const name = typeof body.name === "string" ? body.name : "(unnamed)";
      const rules = Array.isArray(body.rules) ? (body.rules as Array<{ type?: string }>).map((r) => r?.type ?? "?") : [];
      const clash = snap.current.find((r) => r.name === body.name);
      const ok = await confirm.confirm({
        action: "create an organization ruleset (org-wide branch/tag rules)",
        reversible: true,
        target: `${name} in ${o}`,
        details: {
          ruleset: `${name} (target ${show(body.target)}, enforcement ${show(body.enforcement)})`,
          rules: show(rules),
          conditions: body.conditions === undefined ? "none" : JSON.stringify(body.conditions),
          "bypass actors": Array.isArray(body.bypass_actors) ? body.bypass_actors.length : "none",
          "existing rulesets": snap.current.length
            ? `${snap.current.length} — ${snap.current.map((r) => `${r.name} [${show(r.enforcement)}]`).join(", ")}`
            : "0",
          "same name already exists": clash ? `id ${clash.id}` : undefined,
        },
        probe: pinned(snap.version, async () => (await client.rulesetSetSnapshot(o)).version),
      });
      if (!ok.approved) return textResult(`Cancelled — ${ok.reason}.`);
      return jsonResult(await client.createOrgRuleset(o, body));
    },
  },
  {
    name: "protect_branch",
    capability: "write",
    config: {
      title: "Protect a branch",
      description:
        "Apply branch protection to a repository branch. With no explicit rules it applies a sensible default: require a " +
        "pull request with 1 approval, dismiss stale reviews, enforce for admins, and block force-pushes/deletions. " +
        "Honors dry-run and asks a human to approve it (current protection → new) before it writes; the PUT replaces " +
        "the branch's whole protection, so the prompt also lists protections the call does not carry over.",
      inputSchema: {
        org,
        repo,
        branch: z.string().describe("Branch to protect, e.g. main"),
        requiredApprovals: z.number().int().min(0).max(6).optional().describe("Required approving reviews (default 1)"),
        requiredStatusChecks: z.array(z.string()).optional().describe("Status check contexts that must pass (same spelling as requiredApprovals)"),
        requireStatusChecks: z.array(z.string()).optional().describe("Alias of requiredStatusChecks; if both are given the contexts are merged"),
        enforceAdmins: z.boolean().optional().describe("Apply the rules to admins too (default true)"),
      },
    },
    handler: async (a, { client, policy, confirm }) => {
      const o = a.org as string;
      const { dryRun } = policy.guard({ tool: "protect_branch", capability: "write", org: o });
      const approvals = (a.requiredApprovals as number) ?? 1;
      const checks = [...new Set([...((a.requiredStatusChecks as string[] | undefined) ?? []), ...((a.requireStatusChecks as string[] | undefined) ?? [])])];
      const body = {
        required_status_checks: checks.length ? { strict: true, contexts: checks } : null,
        enforce_admins: (a.enforceAdmins as boolean | undefined) ?? true,
        required_pull_request_reviews: { dismiss_stale_reviews: true, required_approving_review_count: approvals },
        restrictions: null,
        allow_force_pushes: false,
        allow_deletions: false,
      };
      if (dryRun) return textResult(`[dry-run] Would protect ${o}/${a.repo}@${a.branch}: ${JSON.stringify(body)}`);
      const repoName = a.repo as string;
      const branch = a.branch as string;
      const snap = await client.branchProtectionSnapshot(o, repoName, branch);
      const cur = snap.current;
      const newChecks = checks.length ? checks : null;
      // `null` in the summary means the feature is off, which reads as "none" in a prompt.
      const none = <T>(v: T | null | undefined): T | "none" => v ?? "none";
      const details: Record<string, string> = {
        "current protection": cur ? "present" : "none",
        "required approving reviews": change(none(cur?.required_approving_reviews), approvals),
        "dismiss stale reviews": change(none(cur?.dismiss_stale_reviews), true),
        "enforce for admins": change(cur?.enforce_admins ?? false, body.enforce_admins),
        "required status checks": change(none(cur?.required_status_checks), none(newChecks)),
        "allow force pushes": change(cur?.allow_force_pushes ?? false, false),
        "allow deletions": change(cur?.allow_deletions ?? false, false),
        "push restrictions": change(none(cur?.push_restrictions), "none"),
      };
      if (cur) {
        const dropped = (
          [
            ["require_code_owner_reviews", cur.require_code_owner_reviews],
            ["required_linear_history", cur.required_linear_history],
            ["required_conversation_resolution", cur.required_conversation_resolution],
          ] as const
        )
          .filter(([, on]) => on === true)
          .map(([k]) => k);
        if (dropped.length) details["not specified by this call (PUT replaces the whole protection), enabled today"] = dropped.join(", ");
      }
      const ok = await confirm.confirm({
        action: "replace branch protection",
        reversible: true,
        target: `${o}/${repoName}@${branch}`,
        details,
        probe: pinned(snap.version, async () => (await client.branchProtectionSnapshot(o, repoName, branch)).version),
      });
      if (!ok.approved) return textResult(`Cancelled — ${ok.reason}.`);
      return jsonResult(await client.putBranchProtection(o, repoName, branch, body));
    },
  },
  {
    name: "update_repo_security",
    capability: "write",
    config: {
      title: "Update repository security settings",
      description:
        "Enable/disable a repository's security_and_analysis features — secret scanning, push protection, and (where " +
        "licensed) GitHub Advanced Security. Honors dry-run and asks a human to approve the change (current → new) " +
        "before it writes.",
      inputSchema: {
        org,
        repo,
        secret_scanning: z.boolean().optional(),
        push_protection: z.boolean().optional(),
        advanced_security: z.boolean().optional(),
      },
    },
    handler: async (a, { client, policy, confirm }) => {
      const o = a.org as string;
      const { dryRun } = policy.guard({ tool: "update_repo_security", capability: "write", org: o });
      const sa: Record<string, unknown> = {};
      if (a.secret_scanning !== undefined) sa.secret_scanning = { status: a.secret_scanning ? "enabled" : "disabled" };
      if (a.push_protection !== undefined) sa.secret_scanning_push_protection = { status: a.push_protection ? "enabled" : "disabled" };
      if (a.advanced_security !== undefined) sa.advanced_security = { status: a.advanced_security ? "enabled" : "disabled" };
      if (Object.keys(sa).length === 0) return { content: [{ type: "text" as const, text: "Nothing to update." }], isError: true };
      const body = { security_and_analysis: sa };
      if (dryRun) return textResult(`[dry-run] Would update security on ${o}/${a.repo}: ${JSON.stringify(body)}`);
      const repoName = a.repo as string;
      const snap = await client.repoSecuritySnapshot(o, repoName);
      const details: Record<string, string> = {};
      for (const [k, v] of Object.entries(sa)) {
        const next = (v as { status: string }).status;
        details[k] = snap ? change(snap.current[k], next) : `(current value unavailable) → ${next}`;
      }
      const ok = await confirm.confirm({
        action: "change repository security settings",
        reversible: true,
        target: `${o}/${repoName}`,
        details,
        probe: pinned(snap?.version, async () => (await client.repoSecuritySnapshot(o, repoName))?.version),
      });
      if (!ok.approved) return textResult(`Cancelled — ${ok.reason}.`);
      return jsonResult(await client.updateRepo(o, repoName, body));
    },
  },
  {
    name: "create_webhook",
    capability: "write",
    config: {
      title: "Create organization webhook",
      description:
        "Create an organization webhook. Provide the payload URL, events, and (recommended) a signing secret — the secret " +
        "is sent to GitHub but never echoed back in any response.",
      inputSchema: {
        org,
        url: z.string().describe("Payload URL (https:// endpoint that receives events)"),
        events: z.array(z.string()).optional().describe("Events to subscribe to; default ['push']"),
        secret: z.string().optional().describe("HMAC signing secret (write-only; never returned)"),
        contentType: z.enum(["json", "form"]).optional().describe("Default json"),
      },
    },
    handler: async (a, { client, policy, confirm }) => {
      const o = a.org as string;
      const { dryRun } = policy.guard({ tool: "create_webhook", capability: "write", org: o });
      const body = {
        name: "web",
        active: true,
        events: (a.events as string[] | undefined) ?? ["push"],
        config: {
          url: a.url as string,
          content_type: (a.contentType as string) ?? "json",
          ...(a.secret ? { secret: a.secret as string } : {}),
        },
      };
      if (dryRun) return textResult(`[dry-run] Would create webhook on '${o}' → ${a.url} for ${body.events.join(", ")}.`);
      const ok = await confirm.confirm({
        action: "create an organization webhook (sends event data off-platform)",
        target: `${o} → ${a.url}`,
        probe: () => client.webhookSetVersion(o),
      });
      if (!ok.approved) return textResult(`Cancelled — ${ok.reason}.`);
      return jsonResult(redact(await client.createWebhook(o, body)));
    },
  },
];
