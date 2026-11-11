import { afterEach, describe, expect, it, vi } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { ElicitRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import type { AppConfig } from "../src/config.js";
import { buildServer } from "../src/server.js";

/**
 * End-to-end approval tests for the org-wide security writes that used to run without a human:
 * update_org_settings, create_org_ruleset, protect_branch, set_actions_permissions, update_repo_security.
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
});

// ---------------------------------------------------------------------------------------------------
describe("set_actions_permissions", () => {
  const PATH = "/orgs/acme/actions/permissions";
  const call = { name: "set_actions_permissions", arguments: { org: "acme", allowed_actions: "local_only" } };
  const CURRENT = { enabled_repositories: "all", allowed_actions: "all" };

  it("asks the human, showing current -> new, then writes", async () => {
    const gh = stubGitHub({ [`GET ${PATH}`]: CURRENT, [`PUT ${PATH}`]: {} });
    const { client, prompts } = await connect();
    await client.callTool(call);
    expect(prompts).toHaveLength(1);
    expect(prompts[0]).toContain("tool: set_actions_permissions");
    expect(prompts[0]).toContain("allowed_actions: all → local_only");
    expect(prompts[0]).toContain("enabled_repositories: all (unchanged)");
    expect(prompts[0]).toMatch(/resource version: [0-9a-f]{12}/);
    expect(gh.writes()).toEqual([{ method: "PUT", path: PATH, body: { allowed_actions: "local_only" } }]);
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
describe("create_repository (additive: deliberately not prompted)", () => {
  it("creates without a prompt, even for a public repository, and without reading GitHub first", async () => {
    const gh = stubGitHub({ "POST /orgs/acme/repos": { id: 1 } });
    const { client, prompts } = await connect();
    await client.callTool({ name: "create_repository", arguments: { org: "acme", name: "new", visibility: "public" } });
    expect(prompts).toHaveLength(0);
    expect(gh.calls.map((c) => c.method)).toEqual(["POST"]);
  });
});
