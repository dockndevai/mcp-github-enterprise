import { afterEach, describe, expect, it, vi } from "vitest";
import { GithubClient } from "../src/github/client.js";

const client = new GithubClient({ apiUrl: "https://api.github.com", token: "t", enterprise: "", requestTimeout: 1000, maxPages: 2 });

/** Stub fetch with a path -> JSON (or status) table. */
function stubApi(routes: Record<string, unknown | number>): string[] {
  const seen: string[] = [];
  vi.stubGlobal("fetch", async (url: URL) => {
    seen.push(url.pathname);
    const r = routes[url.pathname];
    if (typeof r === "number") return { ok: false, status: r, text: async () => "err", headers: new Headers() };
    return { ok: true, status: 200, text: async () => JSON.stringify(r), headers: new Headers() };
  });
  return seen;
}

afterEach(() => vi.unstubAllGlobals());

describe("version tokens", () => {
  it("repoVersion: stable across volatile counters, changes with updated_at, and with a recreate (new id)", async () => {
    const repo = { id: 1, node_id: "R_1", updated_at: "2026-01-01T00:00:00Z", stargazers_count: 1, open_issues_count: 2 };
    stubApi({ "/repos/acme/web": repo });
    const a = await client.repoVersion("acme", "web");
    stubApi({ "/repos/acme/web": { ...repo, stargazers_count: 99, open_issues_count: 50 } });
    expect(await client.repoVersion("acme", "web")).toBe(a);
    stubApi({ "/repos/acme/web": { ...repo, updated_at: "2026-01-02T00:00:00Z" } });
    expect(await client.repoVersion("acme", "web")).not.toBe(a);
    stubApi({ "/repos/acme/web": { ...repo, id: 2, node_id: "R_2" } });
    expect(await client.repoVersion("acme", "web")).not.toBe(a);
  });

  it("returns undefined for a missing object (404) but throws on other errors", async () => {
    stubApi({ "/repos/acme/gone": 404, "/repos/acme/denied": 403 });
    expect(await client.repoVersion("acme", "gone")).toBeUndefined();
    await expect(client.repoVersion("acme", "denied")).rejects.toThrow(/403/);
  });

  it("membershipVersion: changes with role and state, not with unrelated user fields", async () => {
    const m = { role: "member", state: "active", user: { id: 5, login: "bob", site_admin: false } };
    stubApi({ "/orgs/acme/memberships/bob": m });
    const a = await client.membershipVersion("acme", "bob");
    stubApi({ "/orgs/acme/memberships/bob": { ...m, user: { ...m.user, site_admin: true } } });
    expect(await client.membershipVersion("acme", "bob")).toBe(a);
    stubApi({ "/orgs/acme/memberships/bob": { ...m, role: "admin" } });
    expect(await client.membershipVersion("acme", "bob")).not.toBe(a);
    stubApi({ "/orgs/acme/memberships/bob": { ...m, state: "pending" } });
    expect(await client.membershipVersion("acme", "bob")).not.toBe(a);
    stubApi({ "/orgs/acme/memberships/bob": 404 });
    expect(await client.membershipVersion("acme", "bob")).toBeUndefined();
  });

  it("teamVersion: ignores member/repo counts, changes with settings", async () => {
    const t = { id: 3, node_id: "T_3", updated_at: "u1", name: "Core", description: "d", privacy: "closed", permission: "pull", parent: null, members_count: 4, repos_count: 9 };
    stubApi({ "/orgs/acme/teams/core": t });
    const a = await client.teamVersion("acme", "core");
    stubApi({ "/orgs/acme/teams/core": { ...t, members_count: 40, repos_count: 90 } });
    expect(await client.teamVersion("acme", "core")).toBe(a);
    stubApi({ "/orgs/acme/teams/core": { ...t, privacy: "secret" } });
    expect(await client.teamVersion("acme", "core")).not.toBe(a);
  });

  it("rulesetVersion: changes when the rules change even if updated_at does not", async () => {
    const r = { id: 7, updated_at: "u1", name: "main", target: "branch", enforcement: "active", conditions: {}, rules: [{ type: "deletion" }] };
    stubApi({ "/orgs/acme/rulesets/7": r });
    const a = await client.rulesetVersion("acme", 7);
    stubApi({ "/orgs/acme/rulesets/7": { ...r, rules: [{ type: "deletion" }, { type: "non_fast_forward" }] } });
    expect(await client.rulesetVersion("acme", 7)).not.toBe(a);
    stubApi({ "/orgs/acme/rulesets/7": { ...r, enforcement: "disabled" } });
    expect(await client.rulesetVersion("acme", 7)).not.toBe(a);
  });

  it("webhookVersion: never depends on the secret, changes with url/events/active", async () => {
    const h = { id: 9, updated_at: "u1", active: true, events: ["push", "pull_request"], config: { url: "https://x.example/h", content_type: "json", secret: "********" } };
    stubApi({ "/orgs/acme/hooks/9": h });
    const a = await client.webhookVersion("acme", 9);
    expect(a).not.toContain("*");
    stubApi({ "/orgs/acme/hooks/9": { ...h, events: ["pull_request", "push"], config: { ...h.config, secret: "different" } } });
    expect(await client.webhookVersion("acme", 9)).toBe(a);
    stubApi({ "/orgs/acme/hooks/9": { ...h, config: { ...h.config, url: "https://evil.example/h" } } });
    expect(await client.webhookVersion("acme", 9)).not.toBe(a);
  });

  it("webhookSetVersion: changes when a webhook is added", async () => {
    const h = { id: 9, active: true, events: ["push"], config: { url: "https://x.example/h" } };
    stubApi({ "/orgs/acme/hooks": [h] });
    const a = await client.webhookSetVersion("acme");
    stubApi({ "/orgs/acme/hooks": [h, { ...h, id: 10 }] });
    expect(await client.webhookSetVersion("acme")).not.toBe(a);
    stubApi({ "/orgs/acme/hooks": [h] });
    expect(await client.webhookSetVersion("acme")).toBe(a);
  });

  it("orgSettingsVersion: tracks only the keys about to be written", async () => {
    const org = { id: 1, node_id: "O_1", default_repository_permission: "write", description: "x", followers: 1 };
    stubApi({ "/orgs/acme": org });
    const keys = ["default_repository_permission"];
    const a = await client.orgSettingsVersion("acme", keys);
    stubApi({ "/orgs/acme": { ...org, description: "changed", followers: 50 } });
    expect(await client.orgSettingsVersion("acme", keys)).toBe(a);
    stubApi({ "/orgs/acme": { ...org, default_repository_permission: "read" } });
    expect(await client.orgSettingsVersion("acme", keys)).not.toBe(a);
  });
});
