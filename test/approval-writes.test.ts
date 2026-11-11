import { afterEach, describe, expect, it, vi } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { ElicitRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import type { AppConfig } from "../src/config.js";
import { buildServer } from "../src/server.js";

/**
 * End-to-end approval tests for the org-wide security writes that used to run without a human:
 * update_org_settings, create_org_ruleset, protect_branch, set_actions_permissions, update_repo_security;
 * plus harden_org_settings (current → new per field) and create_repository (public / internal only).
 * GitHub is stubbed at the `fetch` level so the real client (snapshot + version tokens) is exercised.
 */

const config = (over: Partial<AppConfig["security"]> = {}): AppConfig => ({
  connection: { apiUrl: "https://api.github.com", token: "t", enterprise: "", requestTimeout: 1000, maxPages: 2 },
  security: {
    mode: "admin",
    orgAllowlist: [],
    protectedOrgs: [],
    allowDelete: true,
    requireConfirmation: true,
    dryRun: false,
    auditLog: false,
    requireHumanApproval: false,
    ...over,
  },
});

type Answer = { action: "accept" | "decline"; content?: Record<string, unknown> };

async function connect(opts: { cfg?: AppConfig; answer?: Answer; elicits?: boolean } = {}) {
  const { server } = buildServer(opts.cfg ?? config());
  const prompts: string[] = [];
  const client = new Client({ name: "t", version: "0" }, { capabilities: opts.elicits === false ? {} : { elicitation: {} } });
  if (opts.elicits !== false) {
    client.setRequestHandler(ElicitRequestSchema, async (req) => {
      prompts.push(req.params.message);
      return opts.answer ?? { action: "accept", content: { confirm: true } };
    });
  }
  const [a, b] = InMemoryTransport.createLinkedPair();
  await Promise.all([server.connect(a), client.connect(b)]);
  return { client, prompts };
}

const text = (r: unknown) => ((r as { content: Array<{ text: string }> }).content[0]?.text ?? "");

interface Call {
  method: string;
  path: string;
  body?: unknown;
}

/** Route table: "METHOD /path" -> body, or a function of the call index (0-based, per route) for state that moves. */
type Route = unknown | ((n: number) => unknown);

function stubGitHub(routes: Record<string, Route>) {
  const calls: Call[] = [];
  const seen = new Map<string, number>();
  vi.stubGlobal("fetch", async (url: URL, init: { method: string; body?: string }) => {
    const key = `${init.method} ${url.pathname}`;
    calls.push({ method: init.method, path: url.pathname, body: init.body ? JSON.parse(init.body) : undefined });
    const n = seen.get(key) ?? 0;
    seen.set(key, n + 1);
    const hit = key in routes;
    const route = routes[key];
    const payload = typeof route === "function" ? (route as (n: number) => unknown)(n) : route;
    return {
      ok: hit,
      status: hit ? 200 : 404,
      headers: { get: () => null },
      text: async () => (hit ? JSON.stringify(payload ?? {}) : '{"message":"Not Found"}'),
    };
  });
  return {
    calls,
    writes: () => calls.filter((c) => c.method !== "GET"),
  };
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
});

const ORG = { id: 1, node_id: "O_1", default_repository_permission: "write", members_can_create_public_repositories: true, web_commit_signoff_required: false };

// ---------------------------------------------------------------------------------------------------
describe("harden_org_settings", () => {
  const call = { name: "harden_org_settings", arguments: { org: "acme", overrides: { web_commit_signoff_required: false, not_a_setting: 1 } } };
  // Everything the baseline sets, in the shape GET /orgs/acme returns it; two fields already match the baseline.
  const HARDEN_ORG = {
    id: 1,
    node_id: "O_1",
    default_repository_permission: "write",
    members_can_create_public_repositories: true,
    members_can_fork_private_repositories: false,
    web_commit_signoff_required: true,
    secret_scanning_enabled_for_new_repositories: false,
    secret_scanning_push_protection_enabled_for_new_repositories: false,
    dependabot_alerts_enabled_for_new_repositories: true,
    dependabot_security_updates_enabled_for_new_repositories: false,
    dependency_graph_enabled_for_new_repositories: false,
  };

  it("shows current -> new for every field (not just a count), marks unchanged ones, then writes", async () => {
    const gh = stubGitHub({ "GET /orgs/acme": HARDEN_ORG, "PATCH /orgs/acme": {} });
    const { client, prompts } = await connect();
    await client.callTool(call);
    expect(prompts).toHaveLength(1);
    expect(prompts[0]).toContain("tool: harden_org_settings");
    expect(prompts[0]).toContain("default_repository_permission: write → read");
    expect(prompts[0]).toContain("members_can_create_public_repositories: true → false");
    expect(prompts[0]).toContain("secret_scanning_enabled_for_new_repositories: false → true");
    expect(prompts[0]).toContain("dependabot_alerts_enabled_for_new_repositories: true (unchanged)");
    expect(prompts[0]).toContain("members_can_fork_private_repositories: false (unchanged)");
    // the override is applied (and shown against the live value), the unknown key is reported, not written
    expect(prompts[0]).toContain("web_commit_signoff_required: true → false");
    expect(prompts[0]).toContain("ignored (not writable): not_a_setting");
    expect(prompts[0]).not.toMatch(/\bfields: \d+/);
    expect(prompts[0]).toMatch(/resource version: 1:O_1:/);
    const [w] = gh.writes();
    expect(w).toMatchObject({ method: "PATCH", path: "/orgs/acme" });
    expect(w?.body).toMatchObject({ default_repository_permission: "read", web_commit_signoff_required: false });
    expect(w?.body).not.toHaveProperty("not_a_setting");
  });

  it("says so when the current values cannot be read, instead of omitting them", async () => {
    stubGitHub({ "PATCH /orgs/acme": {} }); // GET /orgs/acme -> 404
    const { client, prompts } = await connect();
    await client.callTool({ name: "harden_org_settings", arguments: { org: "acme" } });
    expect(prompts[0]).toContain("default_repository_permission: (current value unavailable) → read");
  });

  it("does not write when the human declines", async () => {
    const gh = stubGitHub({ "GET /orgs/acme": HARDEN_ORG, "PATCH /orgs/acme": {} });
    const { client } = await connect({ answer: { action: "decline" } });
    expect(text(await client.callTool(call))).toContain("Cancelled");
    expect(gh.writes()).toHaveLength(0);
  });

  it("does not write when a targeted setting changed while the human was deciding", async () => {
    const gh = stubGitHub({
      "GET /orgs/acme": (n: number) => (n === 0 ? HARDEN_ORG : { ...HARDEN_ORG, default_repository_permission: "admin" }),
      "PATCH /orgs/acme": {},
    });
    const { client } = await connect();
    expect(text(await client.callTool(call))).toContain("resource changed since the prompt");
    expect(gh.writes()).toHaveLength(0);
  });

  it("dry-run returns before reading GitHub or prompting", async () => {
    const gh = stubGitHub({});
    const { client, prompts } = await connect({ cfg: config({ dryRun: true }) });
    expect(text(await client.callTool(call))).toContain("[dry-run]");
    expect(prompts).toHaveLength(0);
    expect(gh.calls).toHaveLength(0);
  });

  it("GHE_REQUIRE_HUMAN_APPROVAL refuses, with no prompt and no write, when the client cannot elicit", async () => {
    const gh = stubGitHub({ "GET /orgs/acme": HARDEN_ORG, "PATCH /orgs/acme": {} });
    const { client, prompts } = await connect({ cfg: config({ requireHumanApproval: true }), elicits: false });
    expect(text(await client.callTool(call))).toContain("no human approval channel");
    expect(prompts).toHaveLength(0);
    expect(gh.writes()).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------------------------------
describe("update_org_settings", () => {
  const call = { name: "update_org_settings", arguments: { org: "acme", settings: { default_repository_permission: "read", web_commit_signoff_required: true, bogus: 1 } } };

  it("asks the human, showing current -> new for each field, then writes", async () => {
    const gh = stubGitHub({ "GET /orgs/acme": ORG, "PATCH /orgs/acme": {} });
    const { client, prompts } = await connect();
    const res = await client.callTool(call);
    expect(prompts).toHaveLength(1);
    expect(prompts[0]).toContain("tool: update_org_settings");
    expect(prompts[0]).toContain("default_repository_permission: write → read");
    expect(prompts[0]).toContain("web_commit_signoff_required: false → true");
    expect(prompts[0]).toContain("ignored (not writable): bogus");
    expect(prompts[0]).toMatch(/resource version: 1:O_1:/);
    expect(prompts[0]).toMatch(/fingerprint: [0-9a-f]{16}/);
    expect(gh.writes()).toEqual([{ method: "PATCH", path: "/orgs/acme", body: { default_repository_permission: "read", web_commit_signoff_required: true } }]);
    expect(text(res)).not.toContain("Cancelled");
  });

  it("marks a field the call would not move as unchanged", async () => {
    stubGitHub({ "GET /orgs/acme": ORG, "PATCH /orgs/acme": {} });
    const { client, prompts } = await connect();
    await client.callTool({ name: "update_org_settings", arguments: { org: "acme", settings: { members_can_create_public_repositories: true } } });
    expect(prompts[0]).toContain("members_can_create_public_repositories: true (unchanged)");
  });

  it("does not write when the human declines", async () => {
    const gh = stubGitHub({ "GET /orgs/acme": ORG, "PATCH /orgs/acme": {} });
    const { client } = await connect({ answer: { action: "decline" } });
    const res = await client.callTool(call);
    expect(text(res)).toContain("Cancelled");
    expect(gh.writes()).toHaveLength(0);
  });

  it("does not write when a targeted setting changed while the human was deciding", async () => {
    const gh = stubGitHub({
      "GET /orgs/acme": (n: number) => (n === 0 ? ORG : { ...ORG, default_repository_permission: "admin" }),
      "PATCH /orgs/acme": {},
    });
    const { client } = await connect();
    const res = await client.callTool(call);
    expect(text(res)).toContain("resource changed since the prompt");
    expect(gh.writes()).toHaveLength(0);
  });

  it("dry-run returns before reading GitHub or prompting", async () => {
    const gh = stubGitHub({});
    const { client, prompts } = await connect({ cfg: config({ dryRun: true }) });
    const res = await client.callTool(call);
    expect(text(res)).toContain("[dry-run]");
    expect(prompts).toHaveLength(0);
    expect(gh.calls).toHaveLength(0);
  });

  it("GHE_REQUIRE_HUMAN_APPROVAL refuses, with no prompt and no write, when the client cannot elicit", async () => {
    const gh = stubGitHub({ "GET /orgs/acme": ORG, "PATCH /orgs/acme": {} });
    const { client, prompts } = await connect({ cfg: config({ requireHumanApproval: true }), elicits: false });
    const res = await client.callTool(call);
    expect(text(res)).toContain("no human approval channel");
    expect(prompts).toHaveLength(0);
    expect(gh.writes()).toHaveLength(0);
  });

  it("still writes on the flags alone when the client cannot elicit (default)", async () => {
    const gh = stubGitHub({ "GET /orgs/acme": ORG, "PATCH /orgs/acme": {} });
    const { client } = await connect({ elicits: false });
    await client.callTool(call);
    expect(gh.writes()).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------------------------------
describe("create_org_ruleset", () => {
  const ruleset = { name: "main-guard", target: "branch", enforcement: "active", rules: [{ type: "pull_request" }, { type: "non_fast_forward" }], conditions: { ref_name: { include: ["~DEFAULT_BRANCH"], exclude: [] } } };
  const call = { name: "create_org_ruleset", arguments: { org: "acme", ruleset } };
  const EXISTING = [{ id: 4, name: "main-guard", target: "branch", enforcement: "evaluate" }, { id: 5, name: "tags", target: "tag", enforcement: "active" }];

  it("asks the human, showing the new ruleset and the rulesets already in place, then creates", async () => {
    const gh = stubGitHub({ "GET /orgs/acme/rulesets": EXISTING, "POST /orgs/acme/rulesets": { id: 9 } });
    const { client, prompts } = await connect();
    await client.callTool(call);
    expect(prompts).toHaveLength(1);
    expect(prompts[0]).toContain("tool: create_org_ruleset");
    expect(prompts[0]).toContain("ruleset: main-guard (target branch, enforcement active)");
    expect(prompts[0]).toContain("rules: pull_request, non_fast_forward");
    expect(prompts[0]).toContain("existing rulesets: 2 — main-guard [evaluate], tags [active]");
    expect(prompts[0]).toContain("same name already exists: id 4");
    expect(prompts[0]).toMatch(/resource version: [0-9a-f]{12}/);
    expect(gh.writes()).toEqual([{ method: "POST", path: "/orgs/acme/rulesets", body: ruleset }]);
  });

  it("does not create when the human declines", async () => {
    const gh = stubGitHub({ "GET /orgs/acme/rulesets": EXISTING, "POST /orgs/acme/rulesets": {} });
    const { client } = await connect({ answer: { action: "decline" } });
    await client.callTool(call);
    expect(gh.writes()).toHaveLength(0);
  });

  it("does not create when the org's rulesets changed while the human was deciding", async () => {
    const gh = stubGitHub({
      "GET /orgs/acme/rulesets": (n: number) => (n === 0 ? EXISTING : [...EXISTING, { id: 6, name: "other", target: "branch", enforcement: "active" }]),
      "POST /orgs/acme/rulesets": {},
    });
    const { client } = await connect();
    const res = await client.callTool(call);
    expect(text(res)).toContain("resource changed since the prompt");
    expect(gh.writes()).toHaveLength(0);
  });

  it("dry-run returns before reading GitHub or prompting", async () => {
    const gh = stubGitHub({});
    const { client, prompts } = await connect({ cfg: config({ dryRun: true }) });
    expect(text(await client.callTool(call))).toContain("[dry-run]");
    expect(prompts).toHaveLength(0);
    expect(gh.calls).toHaveLength(0);
  });

  it("GHE_REQUIRE_HUMAN_APPROVAL refuses, with no prompt and no write, when the client cannot elicit", async () => {
    const gh = stubGitHub({ "GET /orgs/acme/rulesets": EXISTING, "POST /orgs/acme/rulesets": {} });
    const { client, prompts } = await connect({ cfg: config({ requireHumanApproval: true }), elicits: false });
    expect(text(await client.callTool(call))).toContain("no human approval channel");
    expect(prompts).toHaveLength(0);
    expect(gh.writes()).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------------------------------
describe("protect_branch", () => {
  const PATH = "/repos/acme/web/branches/main/protection";
  const call = { name: "protect_branch", arguments: { org: "acme", repo: "web", branch: "main" } };
  const WEAK = {
    required_pull_request_reviews: { dismiss_stale_reviews: false, required_approving_review_count: 3, require_code_owner_reviews: true },
    enforce_admins: { enabled: false },
    allow_force_pushes: { enabled: true },
    allow_deletions: { enabled: false },
    required_linear_history: { enabled: true },
    restrictions: { users: [{ login: "alice" }], teams: [{ slug: "release" }], apps: [] },
  };

  it("asks the human, showing current -> new protection and what the PUT drops, then applies", async () => {
    const gh = stubGitHub({ [`GET ${PATH}`]: WEAK, [`PUT ${PATH}`]: {} });
    const { client, prompts } = await connect();
    await client.callTool(call);
    expect(prompts).toHaveLength(1);
    expect(prompts[0]).toContain("tool: protect_branch");
    expect(prompts[0]).toContain("required approving reviews: 3 → 1");
    expect(prompts[0]).toContain("dismiss stale reviews: false → true");
    expect(prompts[0]).toContain("enforce for admins: false → true");
    expect(prompts[0]).toContain("allow force pushes: true → false");
    expect(prompts[0]).toContain("push restrictions: team:release, user:alice → none");
    expect(prompts[0]).toContain("not specified by this call");
    expect(prompts[0]).toContain("require_code_owner_reviews");
    expect(prompts[0]).toContain("required_linear_history");
    expect(prompts[0]).toMatch(/resource version: [0-9a-f]{12}/);
    expect(gh.writes()).toHaveLength(1);
    expect(gh.writes()[0]).toMatchObject({ method: "PUT", path: PATH });
  });

  it("shows 'not protected' for a branch with no protection", async () => {
    stubGitHub({ [`PUT ${PATH}`]: {} });
    const { client, prompts } = await connect();
    await client.callTool(call);
    expect(prompts[0]).toContain("required approving reviews: none → 1");
    expect(prompts[0]).toContain("current protection: none");
  });

  it("does not write when the human declines", async () => {
    const gh = stubGitHub({ [`GET ${PATH}`]: WEAK, [`PUT ${PATH}`]: {} });
    const { client } = await connect({ answer: { action: "decline" } });
    await client.callTool(call);
    expect(gh.writes()).toHaveLength(0);
  });

  it("does not write when the protection changed while the human was deciding", async () => {
    const gh = stubGitHub({
      [`GET ${PATH}`]: (n: number) => (n === 0 ? WEAK : { ...WEAK, enforce_admins: { enabled: true } }),
      [`PUT ${PATH}`]: {},
    });
    const { client } = await connect();
    expect(text(await client.callTool(call))).toContain("resource changed since the prompt");
    expect(gh.writes()).toHaveLength(0);
  });

  it("dry-run returns before reading GitHub or prompting", async () => {
    const gh = stubGitHub({});
    const { client, prompts } = await connect({ cfg: config({ dryRun: true }) });
    expect(text(await client.callTool(call))).toContain("[dry-run]");
    expect(prompts).toHaveLength(0);
    expect(gh.calls).toHaveLength(0);
  });

  it("GHE_REQUIRE_HUMAN_APPROVAL refuses, with no prompt and no write, when the client cannot elicit", async () => {
    const gh = stubGitHub({ [`GET ${PATH}`]: WEAK, [`PUT ${PATH}`]: {} });
    const { client, prompts } = await connect({ cfg: config({ requireHumanApproval: true }), elicits: false });
    expect(text(await client.callTool(call))).toContain("no human approval channel");
    expect(prompts).toHaveLength(0);
    expect(gh.writes()).toHaveLength(0);
  });

  describe("required status checks", () => {
    const put = async (args: Record<string, unknown>) => {
      const gh = stubGitHub({ [`PUT ${PATH}`]: {} });
      const { client, prompts } = await connect();
      await client.callTool({ name: "protect_branch", arguments: { ...call.arguments, ...args } });
      return { body: gh.writes()[0]?.body as { required_status_checks: unknown } | undefined, prompt: prompts[0] ?? "" };
    };

    it("requiredStatusChecks (spelled like requiredApprovals) reaches the PUT body and the prompt", async () => {
      const { body, prompt } = await put({ requiredStatusChecks: ["ci/build", "ci/test"] });
      expect(body?.required_status_checks).toEqual({ strict: true, contexts: ["ci/build", "ci/test"] });
      expect(prompt).toContain("required status checks: none → ci/build, ci/test");
    });

    it("requireStatusChecks (the original spelling) still works", async () => {
      const { body } = await put({ requireStatusChecks: ["ci/build"] });
      expect(body?.required_status_checks).toEqual({ strict: true, contexts: ["ci/build"] });
    });

    it("both spellings together are merged, without duplicates", async () => {
      const { body } = await put({ requiredStatusChecks: ["a", "b"], requireStatusChecks: ["b", "c"] });
      expect(body?.required_status_checks).toEqual({ strict: true, contexts: ["a", "b", "c"] });
    });

    it("no checks given still sends null", async () => {
      const { body } = await put({});
      expect(body?.required_status_checks).toBeNull();
    });
  });
});

// ---------------------------------------------------------------------------------------------------
describe("set_actions_permissions", () => {
  const PATH = "/orgs/acme/actions/permissions";
  const call = { name: "set_actions_permissions", arguments: { org: "acme", allowed_actions: "local_only" } };
  const CURRENT = { enabled_repositories: "all", allowed_actions: "all" };

  it("asks the human, showing current -> new, then writes a body GitHub accepts (enabled_repositories is required)", async () => {
    const gh = stubGitHub({ [`GET ${PATH}`]: CURRENT, [`PUT ${PATH}`]: {} });
    const { client, prompts } = await connect();
    await client.callTool(call);
    expect(prompts).toHaveLength(1);
    expect(prompts[0]).toContain("tool: set_actions_permissions");
    expect(prompts[0]).toContain("allowed_actions: all → local_only");
    expect(prompts[0]).toContain("enabled_repositories: all (unchanged)");
    expect(prompts[0]).toMatch(/resource version: [0-9a-f]{12}/);
    // read-modify-write: the field the caller did not name keeps its current value
    expect(gh.writes()).toEqual([{ method: "PUT", path: PATH, body: { enabled_repositories: "all", allowed_actions: "local_only" } }]);
  });

  it("setting only enabled_repositories sends just that (allowed_actions is optional in GitHub's contract)", async () => {
    const gh = stubGitHub({ [`GET ${PATH}`]: CURRENT, [`PUT ${PATH}`]: {} });
    const { client, prompts } = await connect();
    await client.callTool({ name: "set_actions_permissions", arguments: { org: "acme", enabled_repositories: "selected" } });
    expect(prompts[0]).toContain("enabled_repositories: all → selected");
    expect(prompts[0]).toContain("allowed_actions: all (unchanged)");
    expect(gh.writes()).toEqual([{ method: "PUT", path: PATH, body: { enabled_repositories: "selected" } }]);
  });

  it("sends back sha_pinning_required when the current policy reports it, and shows it as unchanged", async () => {
    const gh = stubGitHub({ [`GET ${PATH}`]: { ...CURRENT, sha_pinning_required: true }, [`PUT ${PATH}`]: {} });
    const { client, prompts } = await connect();
    await client.callTool(call);
    expect(prompts[0]).toContain("sha_pinning_required: true (unchanged)");
    expect(gh.writes()[0]?.body).toEqual({ enabled_repositories: "all", allowed_actions: "local_only", sha_pinning_required: true });
  });

  it("refuses, without writing, when only allowed_actions is given and the current policy cannot be read", async () => {
    const gh = stubGitHub({ [`PUT ${PATH}`]: {} }); // GET -> 404
    const { client, prompts } = await connect();
    const res = await client.callTool(call);
    expect(res.isError).toBe(true);
    expect(text(res)).toContain("enabled_repositories is required");
    expect(prompts).toHaveLength(0);
    expect(gh.writes()).toHaveLength(0);
  });

  it("still writes when enabled_repositories is given and the current policy cannot be read", async () => {
    const gh = stubGitHub({ [`PUT ${PATH}`]: {} });
    const { client, prompts } = await connect();
    await client.callTool({ name: "set_actions_permissions", arguments: { org: "acme", enabled_repositories: "none" } });
    expect(prompts[0]).toContain("enabled_repositories: (current value unavailable) → none");
    expect(gh.writes()).toEqual([{ method: "PUT", path: PATH, body: { enabled_repositories: "none" } }]);
  });

  it("does not write when the human declines", async () => {
    const gh = stubGitHub({ [`GET ${PATH}`]: CURRENT, [`PUT ${PATH}`]: {} });
    const { client } = await connect({ answer: { action: "decline" } });
    await client.callTool(call);
    expect(gh.writes()).toHaveLength(0);
  });

  it("does not write when the policy changed while the human was deciding", async () => {
    const gh = stubGitHub({
      [`GET ${PATH}`]: (n: number) => (n === 0 ? CURRENT : { ...CURRENT, enabled_repositories: "none" }),
      [`PUT ${PATH}`]: {},
    });
    const { client } = await connect();
    expect(text(await client.callTool(call))).toContain("resource changed since the prompt");
    expect(gh.writes()).toHaveLength(0);
  });

  it("dry-run returns before reading GitHub or prompting", async () => {
    const gh = stubGitHub({});
    const { client, prompts } = await connect({ cfg: config({ dryRun: true }) });
    expect(text(await client.callTool(call))).toContain("[dry-run]");
    expect(prompts).toHaveLength(0);
    expect(gh.calls).toHaveLength(0);
  });

  it("GHE_REQUIRE_HUMAN_APPROVAL refuses, with no prompt and no write, when the client cannot elicit", async () => {
    const gh = stubGitHub({ [`GET ${PATH}`]: CURRENT, [`PUT ${PATH}`]: {} });
    const { client, prompts } = await connect({ cfg: config({ requireHumanApproval: true }), elicits: false });
    expect(text(await client.callTool(call))).toContain("no human approval channel");
    expect(prompts).toHaveLength(0);
    expect(gh.writes()).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------------------------------
describe("update_repo_security", () => {
  const PATH = "/repos/acme/web";
  const call = { name: "update_repo_security", arguments: { org: "acme", repo: "web", secret_scanning: false, push_protection: true } };
  const REPO = {
    id: 7,
    node_id: "R_7",
    updated_at: "2026-01-01T00:00:00Z",
    security_and_analysis: {
      secret_scanning: { status: "enabled" },
      secret_scanning_push_protection: { status: "disabled" },
      advanced_security: { status: "disabled" },
    },
  };

  it("asks the human, showing current -> new for each feature, then writes", async () => {
    const gh = stubGitHub({ [`GET ${PATH}`]: REPO, [`PATCH ${PATH}`]: {} });
    const { client, prompts } = await connect();
    await client.callTool(call);
    expect(prompts).toHaveLength(1);
    expect(prompts[0]).toContain("tool: update_repo_security");
    expect(prompts[0]).toContain("secret_scanning: enabled → disabled");
    expect(prompts[0]).toContain("secret_scanning_push_protection: disabled → enabled");
    expect(prompts[0]).toMatch(/resource version: 7:R_7:/);
    expect(gh.writes()).toHaveLength(1);
    expect(gh.writes()[0]).toMatchObject({ method: "PATCH", path: PATH });
  });

  it("ignores repo activity (updated_at) but catches a security-setting change during the prompt", async () => {
    const gh = stubGitHub({ [`GET ${PATH}`]: (n: number) => (n === 0 ? REPO : { ...REPO, updated_at: "2026-02-02T00:00:00Z" }), [`PATCH ${PATH}`]: {} });
    const { client } = await connect();
    await client.callTool(call);
    expect(gh.writes()).toHaveLength(1);

    const gh2 = stubGitHub({
      [`GET ${PATH}`]: (n: number) => (n === 0 ? REPO : { ...REPO, security_and_analysis: { ...REPO.security_and_analysis, secret_scanning: { status: "disabled" } } }),
      [`PATCH ${PATH}`]: {},
    });
    const second = await connect();
    expect(text(await second.client.callTool(call))).toContain("resource changed since the prompt");
    expect(gh2.writes()).toHaveLength(0);
  });

  it("does not write when the human declines", async () => {
    const gh = stubGitHub({ [`GET ${PATH}`]: REPO, [`PATCH ${PATH}`]: {} });
    const { client } = await connect({ answer: { action: "decline" } });
    await client.callTool(call);
    expect(gh.writes()).toHaveLength(0);
  });

  it("dry-run returns before reading GitHub or prompting", async () => {
    const gh = stubGitHub({});
    const { client, prompts } = await connect({ cfg: config({ dryRun: true }) });
    expect(text(await client.callTool(call))).toContain("[dry-run]");
    expect(prompts).toHaveLength(0);
    expect(gh.calls).toHaveLength(0);
  });

  it("GHE_REQUIRE_HUMAN_APPROVAL refuses, with no prompt and no write, when the client cannot elicit", async () => {
    const gh = stubGitHub({ [`GET ${PATH}`]: REPO, [`PATCH ${PATH}`]: {} });
    const { client, prompts } = await connect({ cfg: config({ requireHumanApproval: true }), elicits: false });
    expect(text(await client.callTool(call))).toContain("no human approval channel");
    expect(prompts).toHaveLength(0);
    expect(gh.writes()).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------------------------------
describe("create_repository", () => {
  const POST = "POST /orgs/acme/repos";
  const make = (visibility?: string) => ({ name: "create_repository", arguments: { org: "acme", name: "new", description: "demo", ...(visibility ? { visibility } : {}) } });

  it.each(["private", undefined])("creates a %s (default) repository without a prompt", async (visibility) => {
    const gh = stubGitHub({ [POST]: { id: 1 } });
    const { client, prompts } = await connect();
    await client.callTool(make(visibility));
    expect(prompts).toHaveLength(0);
    expect(gh.calls.map((c) => c.method)).toEqual(["POST"]);
    expect(gh.writes()[0]?.body).toMatchObject({ visibility: "private", private: true });
  });

  it("a private repository is still created in strict mode when the client cannot elicit", async () => {
    const gh = stubGitHub({ [POST]: { id: 1 } });
    const { client } = await connect({ cfg: config({ requireHumanApproval: true }), elicits: false });
    await client.callTool(make("private"));
    expect(gh.writes()).toHaveLength(1);
  });

  it.each(["public", "internal"])("asks the human before creating a %s repository, then creates it", async (visibility) => {
    const gh = stubGitHub({ [POST]: { id: 1 } });
    const { client, prompts } = await connect();
    await client.callTool(make(visibility));
    expect(prompts).toHaveLength(1);
    expect(prompts[0]).toContain("tool: create_repository");
    expect(prompts[0]).toContain(`create a ${visibility} repository`);
    expect(prompts[0]).toContain("acme/new");
    expect(prompts[0]).toContain(`visibility: ${visibility}`);
    expect(prompts[0]).toMatch(/fingerprint: [0-9a-f]{16}/);
    expect(gh.writes()).toHaveLength(1);
    expect(gh.writes()[0]?.body).toMatchObject({ visibility, name: "new" });
  });

  it("does not create a public repository when the human declines", async () => {
    const gh = stubGitHub({ [POST]: { id: 1 } });
    const { client } = await connect({ answer: { action: "decline" } });
    expect(text(await client.callTool(make("public")))).toContain("Cancelled");
    expect(gh.writes()).toHaveLength(0);
  });

  it("dry-run returns before prompting or calling GitHub", async () => {
    const gh = stubGitHub({});
    const { client, prompts } = await connect({ cfg: config({ dryRun: true }) });
    expect(text(await client.callTool(make("public")))).toContain("[dry-run]");
    expect(prompts).toHaveLength(0);
    expect(gh.calls).toHaveLength(0);
  });

  it("GHE_REQUIRE_HUMAN_APPROVAL refuses a public repository, with no prompt and no write, when the client cannot elicit", async () => {
    const gh = stubGitHub({ [POST]: { id: 1 } });
    const { client, prompts } = await connect({ cfg: config({ requireHumanApproval: true }), elicits: false });
    expect(text(await client.callTool(make("public")))).toContain("no human approval channel");
    expect(prompts).toHaveLength(0);
    expect(gh.writes()).toHaveLength(0);
  });

  it("still creates a public repository on the flags alone when the client cannot elicit (default)", async () => {
    const gh = stubGitHub({ [POST]: { id: 1 } });
    const { client } = await connect({ elicits: false });
    await client.callTool(make("public"));
    expect(gh.writes()).toHaveLength(1);
  });
});
