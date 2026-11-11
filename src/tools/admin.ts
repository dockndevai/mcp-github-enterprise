import { z } from "zod";
import type { ToolDef } from "./types.js";
import { jsonResult, textResult } from "./types.js";

const org = z.string().describe("Organization login (must be within GHE_ORG_ALLOWLIST when that is set)");

/**
 * Admin tools. create_repository needs admin mode. The delete/remove operations
 * are high-impact: admin mode + GHE_ALLOW_DELETE + a typed confirmation matching
 * the exact target, and a human elicitation prompt when the client supports one.
 */
export const adminTools: ToolDef[] = [
  {
    name: "create_repository",
    capability: "admin",
    config: {
      title: "Create repository",
      description:
        "Create a repository in an organization. Requires admin mode. Defaults to private with auto-init; secret scanning " +
        "and push protection are requested on creation where the plan allows. A public or internal repository asks a human " +
        "to approve it first (a private one does not).",
      inputSchema: {
        org,
        name: z.string().describe("Repository name"),
        description: z.string().optional(),
        visibility: z.enum(["private", "internal", "public"]).optional().describe("Default private"),
        autoInit: z.boolean().optional().describe("Initialize with a README (default true)"),
      },
    },
    handler: async (a, { client, policy, confirm }) => {
      const o = a.org as string;
      const { dryRun } = policy.guard({ tool: "create_repository", capability: "admin", org: o });
      const visibility = (a.visibility as string) ?? "private";
      const body = {
        name: a.name,
        description: a.description,
        visibility,
        private: visibility !== "public",
        auto_init: (a.autoInit as boolean | undefined) ?? true,
      };
      if (dryRun) return textResult(`[dry-run] Would create ${visibility} repo '${o}/${a.name}'.`);
      // A private repository is additive and stays unprompted (a new, empty repository, private by default, behind the
      // admin-mode gate and the org allowlist). A public or internal one widens who can read what is pushed to it next, so
      // a human approves it; with GHE_REQUIRE_HUMAN_APPROVAL=true it is refused when no human can be asked.
      if (visibility !== "private") {
        const ok = await confirm.confirm({
          action: `create a ${visibility} repository`,
          reversible: true,
          target: `${o}/${a.name}`,
          details: {
            visibility,
            description: a.description === undefined ? undefined : String(a.description),
            "initialize with README": body.auto_init,
          },
        });
        if (!ok.approved) return textResult(`Cancelled — ${ok.reason}.`);
      }
      return jsonResult(await client.createRepo(o, body));
    },
  },
  {
    name: "delete_repository",
    capability: "admin",
    destructive: true,
    config: {
      title: "Delete repository",
      description:
        "Permanently delete a repository (code, issues, PRs, releases). Requires admin mode, GHE_ALLOW_DELETE=true, and a " +
        "typed confirmation equal to 'org/repo'. Irreversible.",
      inputSchema: {
        org,
        repo: z.string().describe("Repository name"),
        confirm: z.string().optional().describe("Must equal 'org/repo' to proceed"),
      },
    },
    handler: async (a, { client, policy, confirm }) => {
      const o = a.org as string;
      const target = `${o}/${a.repo}`;
      const { dryRun } = policy.guard({
        tool: "delete_repository",
        capability: "admin",
        org: o,
        destructive: true,
        confirmExpected: target,
        confirmProvided: a.confirm as string | undefined,
      });
      if (dryRun) return textResult(`[dry-run] Would delete repository '${target}'.`);
      const ok = await confirm.confirm({
        action: "delete repository (code, issues, PRs, releases)",
        target,
        typed: true,
        probe: () => client.repoVersion(o, a.repo as string),
      });
      if (!ok.approved) return textResult(`Deletion cancelled — ${ok.reason}.`);
      await client.deleteRepo(o, a.repo as string);
      return jsonResult({ deleted: true, repository: target });
    },
  },
  {
    name: "remove_member",
    capability: "admin",
    destructive: true,
    config: {
      title: "Remove organization member",
      description:
        "Remove a user from the organization (revokes access to all org repos and teams). Requires admin mode, " +
        "GHE_ALLOW_DELETE=true, and a typed confirmation equal to the username.",
      inputSchema: {
        org,
        username: z.string().describe("GitHub login to remove"),
        confirm: z.string().optional().describe("Must equal the username to proceed"),
      },
    },
    handler: async (a, { client, policy, confirm }) => {
      const o = a.org as string;
      const username = a.username as string;
      const { dryRun } = policy.guard({
        tool: "remove_member",
        capability: "admin",
        org: o,
        destructive: true,
        confirmExpected: username,
        confirmProvided: a.confirm as string | undefined,
      });
      if (dryRun) return textResult(`[dry-run] Would remove '${username}' from '${o}'.`);
      const ok = await confirm.confirm({
        action: "remove member from the organization",
        target: `${username} in ${o}`,
        probe: () => client.membershipVersion(o, username),
      });
      if (!ok.approved) return textResult(`Removal cancelled — ${ok.reason}.`);
      await client.removeMember(o, username);
      return jsonResult({ removed: true, org: o, username });
    },
  },
  {
    name: "delete_team",
    capability: "admin",
    destructive: true,
    config: {
      title: "Delete team",
      description:
        "Delete a team (and its sub-teams' parent link). Requires admin mode, GHE_ALLOW_DELETE=true, and a typed " +
        "confirmation equal to the team slug.",
      inputSchema: {
        org,
        slug: z.string().describe("Team slug (from list_teams)"),
        confirm: z.string().optional().describe("Must equal the team slug to proceed"),
      },
    },
    handler: async (a, { client, policy, confirm }) => {
      const o = a.org as string;
      const slug = a.slug as string;
      const { dryRun } = policy.guard({
        tool: "delete_team",
        capability: "admin",
        org: o,
        destructive: true,
        confirmExpected: slug,
        confirmProvided: a.confirm as string | undefined,
      });
      if (dryRun) return textResult(`[dry-run] Would delete team '${slug}' in '${o}'.`);
      const ok = await confirm.confirm({
        action: "delete team",
        target: `${slug} in ${o}`,
        probe: () => client.teamVersion(o, slug),
      });
      if (!ok.approved) return textResult(`Deletion cancelled — ${ok.reason}.`);
      await client.deleteTeam(o, slug);
      return jsonResult({ deleted: true, org: o, team: slug });
    },
  },
  {
    name: "delete_org_ruleset",
    capability: "admin",
    destructive: true,
    config: {
      title: "Delete organization ruleset",
      description:
        "Delete an org ruleset (removes that branch/tag protection org-wide). Requires admin mode, GHE_ALLOW_DELETE=true, " +
        "and a typed confirmation equal to the ruleset id.",
      inputSchema: {
        org,
        rulesetId: z.number().int().describe("Ruleset id (from list_org_rulesets)"),
        confirm: z.string().optional().describe("Must equal the ruleset id to proceed"),
      },
    },
    handler: async (a, { client, policy, confirm }) => {
      const o = a.org as string;
      const id = a.rulesetId as number;
      const { dryRun } = policy.guard({
        tool: "delete_org_ruleset",
        capability: "admin",
        org: o,
        destructive: true,
        confirmExpected: String(id),
        confirmProvided: a.confirm as string | undefined,
      });
      if (dryRun) return textResult(`[dry-run] Would delete ruleset ${id} in '${o}'.`);
      const ok = await confirm.confirm({
        action: "delete org ruleset (removes org-wide protection)",
        target: `ruleset ${id} in ${o}`,
        probe: () => client.rulesetVersion(o, id),
      });
      if (!ok.approved) return textResult(`Deletion cancelled — ${ok.reason}.`);
      await client.deleteOrgRuleset(o, id);
      return jsonResult({ deleted: true, org: o, rulesetId: id });
    },
  },
  {
    name: "delete_webhook",
    capability: "admin",
    destructive: true,
    config: {
      title: "Delete organization webhook",
      description:
        "Delete an organization webhook. Requires admin mode, GHE_ALLOW_DELETE=true, and a typed confirmation equal to the " +
        "webhook id.",
      inputSchema: {
        org,
        hookId: z.number().int().describe("Webhook id (from list_webhooks)"),
        confirm: z.string().optional().describe("Must equal the webhook id to proceed"),
      },
    },
    handler: async (a, { client, policy, confirm }) => {
      const o = a.org as string;
      const id = a.hookId as number;
      const { dryRun } = policy.guard({
        tool: "delete_webhook",
        capability: "admin",
        org: o,
        destructive: true,
        confirmExpected: String(id),
        confirmProvided: a.confirm as string | undefined,
      });
      if (dryRun) return textResult(`[dry-run] Would delete webhook ${id} in '${o}'.`);
      const ok = await confirm.confirm({
        action: "delete org webhook",
        target: `webhook ${id} in ${o}`,
        probe: () => client.webhookVersion(o, id),
      });
      if (!ok.approved) return textResult(`Deletion cancelled — ${ok.reason}.`);
      await client.deleteWebhook(o, id);
      return jsonResult({ deleted: true, org: o, hookId: id });
    },
  },
];
