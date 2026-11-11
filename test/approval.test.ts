import { afterEach, describe, expect, it, vi } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { ElicitRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { loadConfig, type AppConfig } from "../src/config.js";
import { GithubClient } from "../src/github/client.js";
import { buildServer } from "../src/server.js";

const config = (requireHumanApproval = false): AppConfig => ({
  connection: { apiUrl: "https://api.github.com", token: "t", enterprise: "", requestTimeout: 1000, maxPages: 1 },
  security: {
    mode: "admin",
    orgAllowlist: [],
    protectedOrgs: [],
    allowDelete: true,
    requireConfirmation: true,
    dryRun: false,
    auditLog: false,
    requireHumanApproval,
  },
});

type Answer = { action: "accept" | "decline"; content?: Record<string, unknown> };

/** Connect an in-memory MCP client (optionally able to answer elicitation) to a freshly built server. */
async function connect(opts: { cfg?: AppConfig; answer?: (message: string) => Answer | Promise<Answer>; elicits?: boolean }) {
  const { server } = buildServer(opts.cfg ?? config());
  const prompts: string[] = [];
  const client = new Client({ name: "t", version: "0" }, { capabilities: opts.elicits === false ? {} : { elicitation: {} } });
  if (opts.elicits !== false) {
    client.setRequestHandler(ElicitRequestSchema, async (req) => {
      prompts.push(req.params.message);
      return (await opts.answer?.(req.params.message)) ?? { action: "accept", content: { confirm: true, typed: "acme/web" } };
    });
  }
  const [a, b] = InMemoryTransport.createLinkedPair();
  await Promise.all([server.connect(a), client.connect(b)]);
  return { client, prompts };
}

const text = (r: unknown) => ((r as { content: Array<{ text: string }> }).content[0]?.text ?? "");

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
});

const DELETE_REPO = { name: "delete_repository", arguments: { org: "acme", repo: "web", confirm: "acme/web" } };

describe("delete_repository approval (end to end)", () => {
  it("shows the tool, full arguments, version and fingerprint, asks for the typed name, then deletes", async () => {
    vi.spyOn(GithubClient.prototype, "repoVersion").mockResolvedValue("v1");
    const del = vi.spyOn(GithubClient.prototype, "deleteRepo").mockResolvedValue(undefined);
    const { client, prompts } = await connect({});
    const res = await client.callTool(DELETE_REPO);
    expect(text(res)).toContain('"deleted": true');
    expect(del).toHaveBeenCalledWith("acme", "web");
    expect(prompts).toHaveLength(1);
    expect(prompts[0]).toContain("tool: delete_repository");
    expect(prompts[0]).toContain('{"confirm":"acme/web","org":"acme","repo":"web"}');
    expect(prompts[0]).toContain("resource version: v1");
    expect(prompts[0]).toMatch(/fingerprint: [0-9a-f]{16}/);
  });

  it("does NOT delete when the repository changed while the human was deciding", async () => {
    const versions = ["v1", "v2"];
    vi.spyOn(GithubClient.prototype, "repoVersion").mockImplementation(async () => versions.shift());
    const del = vi.spyOn(GithubClient.prototype, "deleteRepo").mockResolvedValue(undefined);
    const { client } = await connect({});
    const res = await client.callTool(DELETE_REPO);
    expect(text(res)).toContain("resource changed since the prompt");
    expect(del).not.toHaveBeenCalled();
  });

  it("does NOT delete when the typed full_name does not match", async () => {
    vi.spyOn(GithubClient.prototype, "repoVersion").mockResolvedValue("v1");
    const del = vi.spyOn(GithubClient.prototype, "deleteRepo").mockResolvedValue(undefined);
    const { client } = await connect({ answer: () => ({ action: "accept", content: { confirm: true, typed: "acme/other" } }) });
    const res = await client.callTool(DELETE_REPO);
    expect(text(res)).toContain("typed confirmation did not match");
    expect(del).not.toHaveBeenCalled();
  });

  it("does NOT delete when the human declines", async () => {
    vi.spyOn(GithubClient.prototype, "repoVersion").mockResolvedValue("v1");
    const del = vi.spyOn(GithubClient.prototype, "deleteRepo").mockResolvedValue(undefined);
    const { client } = await connect({ answer: () => ({ action: "decline" }) });
    await client.callTool(DELETE_REPO);
    expect(del).not.toHaveBeenCalled();
  });
});

describe("GHE_REQUIRE_HUMAN_APPROVAL", () => {
  it("falls back to the flags when the client cannot elicit (default)", async () => {
    vi.spyOn(GithubClient.prototype, "repoVersion").mockResolvedValue("v1");
    const del = vi.spyOn(GithubClient.prototype, "deleteRepo").mockResolvedValue(undefined);
    const { client } = await connect({ elicits: false });
    await client.callTool(DELETE_REPO);
    expect(del).toHaveBeenCalledWith("acme", "web");
  });

  it("is read from the environment, defaulting to false", () => {
    vi.stubEnv("GHE_TOKEN", "t");
    expect(loadConfig().security.requireHumanApproval).toBe(false);
    vi.stubEnv("GHE_REQUIRE_HUMAN_APPROVAL", "true");
    expect(loadConfig().security.requireHumanApproval).toBe(true);
  });

  it("refuses to delete, with no prompt, when the env var is set and the client cannot elicit", async () => {
    vi.stubEnv("GHE_TOKEN", "t");
    vi.stubEnv("GHE_MODE", "admin");
    vi.stubEnv("GHE_ALLOW_DELETE", "true");
    vi.stubEnv("GHE_AUDIT_LOG", "false");
    vi.stubEnv("GHE_REQUIRE_HUMAN_APPROVAL", "true");
    vi.spyOn(GithubClient.prototype, "repoVersion").mockResolvedValue("v1");
    const del = vi.spyOn(GithubClient.prototype, "deleteRepo").mockResolvedValue(undefined);
    const { client, prompts } = await connect({ cfg: loadConfig(), elicits: false });
    const res = await client.callTool(DELETE_REPO);
    expect(text(res)).toContain("no human approval channel");
    expect(prompts).toHaveLength(0);
    expect(del).not.toHaveBeenCalled();
  });
});

// Every confirm site that guards a destructive or high-impact write: a moved version blocks the backend call,
// a stable version lets it through.
const SITES: Array<{
  tool: string;
  args: Record<string, unknown>;
  version: keyof GithubClient;
  mutation: keyof GithubClient;
}> = [
  { tool: "delete_repository", args: DELETE_REPO.arguments, version: "repoVersion", mutation: "deleteRepo" },
  { tool: "remove_member", args: { org: "acme", username: "bob", confirm: "bob" }, version: "membershipVersion", mutation: "removeMember" },
  { tool: "delete_team", args: { org: "acme", slug: "core", confirm: "core" }, version: "teamVersion", mutation: "deleteTeam" },
  { tool: "delete_org_ruleset", args: { org: "acme", rulesetId: 7, confirm: "7" }, version: "rulesetVersion", mutation: "deleteOrgRuleset" },
  { tool: "delete_webhook", args: { org: "acme", hookId: 9, confirm: "9" }, version: "webhookVersion", mutation: "deleteWebhook" },
  { tool: "harden_org_settings", args: { org: "acme" }, version: "orgSettingsVersion", mutation: "updateOrg" },
  { tool: "set_member_role", args: { org: "acme", username: "bob", role: "admin" }, version: "membershipVersion", mutation: "setMembership" },
  { tool: "create_webhook", args: { org: "acme", url: "https://hooks.example.com/x", secret: "s3cr3t" }, version: "webhookSetVersion", mutation: "createWebhook" },
];

describe.each(SITES)("$tool binds its target version", ({ tool, args, version, mutation }) => {
  it("refuses, and does not call GitHub, when the version moved during the prompt", async () => {
    const versions = ["a", "b"];
    vi.spyOn(GithubClient.prototype, version as "repoVersion").mockImplementation(async () => versions.shift());
    const mutate = vi.spyOn(GithubClient.prototype, mutation as "deleteRepo").mockResolvedValue(undefined as never);
    const { client } = await connect({});
    const res = await client.callTool({ name: tool, arguments: args });
    expect(text(res)).toContain("resource changed since the prompt");
    expect(mutate).not.toHaveBeenCalled();
  });

  it("proceeds when the version is stable, and shows the tool, arguments and fingerprint", async () => {
    vi.spyOn(GithubClient.prototype, version as "repoVersion").mockResolvedValue("a");
    const mutate = vi.spyOn(GithubClient.prototype, mutation as "deleteRepo").mockResolvedValue({} as never);
    const { client, prompts } = await connect({});
    await client.callTool({ name: tool, arguments: args });
    expect(mutate).toHaveBeenCalledOnce();
    expect(prompts[0]).toContain(`tool: ${tool}`);
    expect(prompts[0]).toContain("resource version: a");
    expect(prompts[0]).toMatch(/fingerprint: [0-9a-f]{16}/);
  });

  it("does not run without a human when GHE_REQUIRE_HUMAN_APPROVAL is on and the client cannot elicit", async () => {
    vi.spyOn(GithubClient.prototype, version as "repoVersion").mockResolvedValue("a");
    const mutate = vi.spyOn(GithubClient.prototype, mutation as "deleteRepo").mockResolvedValue({} as never);
    const { client } = await connect({ cfg: config(true), elicits: false });
    const res = await client.callTool({ name: tool, arguments: args });
    expect(text(res)).toContain("no human approval channel");
    expect(mutate).not.toHaveBeenCalled();
  });
});

describe("secrets never reach the prompt", () => {
  it("redacts the webhook signing secret from the approval prompt", async () => {
    vi.spyOn(GithubClient.prototype, "webhookSetVersion").mockResolvedValue("a");
    vi.spyOn(GithubClient.prototype, "createWebhook").mockResolvedValue({});
    const { client, prompts } = await connect({});
    await client.callTool({ name: "create_webhook", arguments: { org: "acme", url: "https://hooks.example.com/x", secret: "s3cr3t" } });
    expect(prompts[0]).toContain("[redacted]");
    expect(prompts[0]).not.toContain("s3cr3t");
  });
});

describe("laya-guard confirmation is bound to the call too", () => {
  it("shows the tool and fingerprint when laya-guard asks for a human", async () => {
    vi.stubEnv("GHE_GUARD_MODE", "enforce");
    vi.stubGlobal("fetch", async () => ({
      ok: true,
      json: async () => ({ decision: "confirm", risk: "high", confidence: 1, reasons: ["r"], deterministic: true, model_available: true }),
    }));
    vi.spyOn(GithubClient.prototype, "updateOrg").mockResolvedValue({});
    vi.spyOn(GithubClient.prototype, "orgSettingsVersion").mockResolvedValue("a");
    const { client, prompts } = await connect({ answer: () => ({ action: "decline" }) });
    const res = await client.callTool({ name: "update_org_settings", arguments: { org: "acme", settings: { default_repository_permission: "read" } } });
    expect(text(res)).toContain("Cancelled");
    expect(prompts[0]).toContain("tool: update_org_settings");
    expect(prompts[0]).toMatch(/fingerprint: [0-9a-f]{16}/);
  });
});
