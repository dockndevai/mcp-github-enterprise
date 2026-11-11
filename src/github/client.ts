/**
 * Thin fetch-based client for the GitHub REST API (Cloud & Enterprise Server).
 * Auth is a bearer token (fine-grained PAT, classic PAT, or App installation token).
 * https://docs.github.com/rest
 *
 * Optimizations baked in:
 *   - Keyset auto-pagination that follows the RFC 5988 `Link: rel="next"` header,
 *     capped by GHE_MAX_PAGES so a huge org can't exhaust memory or rate limit.
 *   - Per-request timeout via AbortController.
 *   - Rate-limit headers surfaced so callers can back off before a 403.
 */
import { createHash } from "node:crypto";
import type { GithubConnection } from "../config.js";

export class GithubError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly body?: string,
    readonly rateLimitRemaining?: string,
  ) {
    super(message);
    this.name = "GithubError";
  }
}

export interface RequestOpts {
  query?: Record<string, string | number | boolean | undefined>;
  body?: unknown;
  /** Accept override (e.g. a preview media type). */
  accept?: string;
}

export class GithubClient {
  private readonly auth: string;

  constructor(private readonly conn: GithubConnection) {
    this.auth = `Bearer ${conn.token}`;
  }

  private url(path: string, query?: RequestOpts["query"]): URL {
    const url = new URL(`${this.conn.apiUrl}${path}`);
    for (const [k, v] of Object.entries(query ?? {})) if (v !== undefined) url.searchParams.set(k, String(v));
    return url;
  }

  private headers(accept?: string): Record<string, string> {
    return {
      Authorization: this.auth,
      Accept: accept ?? "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28",
    };
  }

  /** Low-level single request. */
  async request<T = unknown>(method: string, path: string, opts: RequestOpts = {}): Promise<T> {
    const res = await this.fetch(method, this.url(path, opts.query), opts);
    const text = await res.text();
    return (text ? JSON.parse(text) : undefined) as T;
  }

  private async fetch(method: string, url: URL, opts: RequestOpts): Promise<Response> {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), this.conn.requestTimeout);
    try {
      const res = await fetch(url, {
        method,
        headers: {
          ...this.headers(opts.accept),
          ...(opts.body !== undefined ? { "Content-Type": "application/json" } : {}),
        },
        body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
        signal: ctrl.signal,
      });
      if (!res.ok) {
        const body = await res.text();
        throw new GithubError(
          `GitHub ${method} ${url.pathname} failed with ${res.status}.`,
          res.status,
          body,
          res.headers.get("x-ratelimit-remaining") ?? undefined,
        );
      }
      return res;
    } finally {
      clearTimeout(timer);
    }
  }

  /**
   * GET a collection, auto-following `Link: rel="next"` up to maxPages.
   * Returns the concatenated array. Works for endpoints that return a bare
   * array; for wrapped responses pass `extract` to pull the array out.
   */
  async paginate<T = unknown>(
    path: string,
    query: RequestOpts["query"] = {},
    extract?: (page: unknown) => T[],
  ): Promise<T[]> {
    const out: T[] = [];
    let next: URL | null = this.url(path, { per_page: 100, ...query });
    let pages = 0;
    while (next && pages < this.conn.maxPages) {
      const res: Response = await this.fetch("GET", next, {});
      const text = await res.text();
      const json: unknown = text ? JSON.parse(text) : [];
      const items: T[] = extract ? extract(json) : (json as T[]);
      if (Array.isArray(items)) out.push(...items);
      next = parseNextLink(res.headers.get("link"));
      pages += 1;
    }
    return out;
  }

  // --- Identity / limits ------------------------------------------------------
  whoami() {
    return this.request("GET", "/user");
  }
  rateLimit() {
    return this.request("GET", "/rate_limit");
  }

  // --- Organizations ----------------------------------------------------------
  listOrgs() {
    return this.paginate("/user/orgs");
  }
  getOrg(org: string) {
    return this.request("GET", `/orgs/${enc(org)}`);
  }
  updateOrg(org: string, body: Record<string, unknown>) {
    return this.request("PATCH", `/orgs/${enc(org)}`, { body });
  }
  listMembers(org: string, role?: string) {
    return this.paginate(`/orgs/${enc(org)}/members`, role ? { role } : {});
  }
  setMembership(org: string, username: string, role: string) {
    return this.request("PUT", `/orgs/${enc(org)}/memberships/${enc(username)}`, { body: { role } });
  }
  removeMember(org: string, username: string) {
    return this.request("DELETE", `/orgs/${enc(org)}/members/${enc(username)}`);
  }
  listSecurityManagers(org: string) {
    return this.request("GET", `/orgs/${enc(org)}/security-managers`);
  }

  // --- Teams ------------------------------------------------------------------
  listTeams(org: string) {
    return this.paginate(`/orgs/${enc(org)}/teams`);
  }
  createTeam(org: string, body: Record<string, unknown>) {
    return this.request("POST", `/orgs/${enc(org)}/teams`, { body });
  }
  deleteTeam(org: string, slug: string) {
    return this.request("DELETE", `/orgs/${enc(org)}/teams/${enc(slug)}`);
  }

  // --- Repositories -----------------------------------------------------------
  listRepos(org: string, type?: string) {
    return this.paginate(`/orgs/${enc(org)}/repos`, { sort: "full_name", type });
  }
  getRepo(org: string, repo: string) {
    return this.request("GET", `/repos/${enc(org)}/${enc(repo)}`);
  }
  createRepo(org: string, body: Record<string, unknown>) {
    return this.request("POST", `/orgs/${enc(org)}/repos`, { body });
  }
  updateRepo(org: string, repo: string, body: Record<string, unknown>) {
    return this.request("PATCH", `/repos/${enc(org)}/${enc(repo)}`, { body });
  }
  deleteRepo(org: string, repo: string) {
    return this.request("DELETE", `/repos/${enc(org)}/${enc(repo)}`);
  }
  getBranchProtection(org: string, repo: string, branch: string) {
    return this.request("GET", `/repos/${enc(org)}/${enc(repo)}/branches/${enc(branch)}/protection`);
  }
  putBranchProtection(org: string, repo: string, branch: string, body: Record<string, unknown>) {
    return this.request("PUT", `/repos/${enc(org)}/${enc(repo)}/branches/${enc(branch)}/protection`, { body });
  }

  // --- Rulesets ---------------------------------------------------------------
  listOrgRulesets(org: string) {
    return this.request("GET", `/orgs/${enc(org)}/rulesets`);
  }
  createOrgRuleset(org: string, body: Record<string, unknown>) {
    return this.request("POST", `/orgs/${enc(org)}/rulesets`, { body });
  }
  deleteOrgRuleset(org: string, id: number) {
    return this.request("DELETE", `/orgs/${enc(org)}/rulesets/${id}`);
  }

  // --- Webhooks ---------------------------------------------------------------
  listWebhooks(org: string) {
    return this.request("GET", `/orgs/${enc(org)}/hooks`);
  }
  createWebhook(org: string, body: Record<string, unknown>) {
    return this.request("POST", `/orgs/${enc(org)}/hooks`, { body });
  }
  deleteWebhook(org: string, id: number) {
    return this.request("DELETE", `/orgs/${enc(org)}/hooks/${id}`);
  }

  // --- Actions (CI/CD) --------------------------------------------------------
  getActionsPermissions(org: string) {
    return this.request("GET", `/orgs/${enc(org)}/actions/permissions`);
  }
  setActionsPermissions(org: string, body: Record<string, unknown>) {
    return this.request("PUT", `/orgs/${enc(org)}/actions/permissions`, { body });
  }
  listSelfHostedRunners(org: string) {
    return this.request("GET", `/orgs/${enc(org)}/actions/runners`);
  }
  listRunnerGroups(org: string) {
    return this.request("GET", `/orgs/${enc(org)}/actions/runner-groups`);
  }
  getOrgCacheUsage(org: string) {
    return this.request("GET", `/orgs/${enc(org)}/actions/cache/usage`);
  }
  getRepoCacheUsage(org: string, repo: string) {
    return this.request("GET", `/repos/${enc(org)}/${enc(repo)}/actions/cache/usage`);
  }
  listWorkflows(org: string, repo: string) {
    return this.request("GET", `/repos/${enc(org)}/${enc(repo)}/actions/workflows`);
  }

  // --- Security alerts --------------------------------------------------------
  listSecretScanningAlerts(org: string, state?: string) {
    return this.paginate(`/orgs/${enc(org)}/secret-scanning/alerts`, { state });
  }
  listCodeScanningAlerts(org: string, state?: string) {
    return this.paginate(`/orgs/${enc(org)}/code-scanning/alerts`, { state });
  }
  listDependabotAlerts(org: string, state?: string) {
    return this.paginate(`/orgs/${enc(org)}/dependabot/alerts`, { state });
  }

  // --- Audit log --------------------------------------------------------------
  orgAuditLog(org: string, phrase?: string, perPage = 50) {
    return this.request("GET", `/orgs/${enc(org)}/audit-log`, { query: { phrase, per_page: perPage } });
  }
  enterpriseAuditLog(enterprise: string, phrase?: string, perPage = 50) {
    return this.request("GET", `/enterprises/${enc(enterprise)}/audit-log`, { query: { phrase, per_page: perPage } });
  }

  // --- Version tokens (pinned across a human-approval prompt) ------------------
  // Each returns a short, stable token for the target, or `undefined` when it does not exist (404).
  // Transport / auth errors propagate: the confirmer treats a failing first probe as "unbound" and a
  // failing second probe as a changed resource. Volatile counters (stars, open issues, member counts)
  // are deliberately NOT part of any token — they would make every approval fail on a busy target.

  /**
   * Repository: immutable `id` + `node_id` (a delete-and-recreate under the same name gets a new id)
   * and GitHub's `updated_at`. A change that GitHub does not reflect in `updated_at` (or two changes
   * within its one-second resolution) is not detected; the stable `id` is what rules out a recreate.
   */
  async repoVersion(org: string, repo: string): Promise<string | undefined> {
    const r = await this.getOrUndefined<{ id: number; node_id: string; updated_at: string }>(`/repos/${enc(org)}/${enc(repo)}`);
    return r ? `${r.id}:${r.node_id}:${r.updated_at}` : undefined;
  }

  /**
   * Organization membership: the user's immutable id, role and state (active / pending). Detects a role
   * change or a pending-invite -> active transition during the prompt. A user who left and was re-added
   * with the same role is not distinguishable. `undefined` when the user has no membership.
   */
  async membershipVersion(org: string, username: string): Promise<string | undefined> {
    const m = await this.getOrUndefined<{ role: string; state: string; user?: { id: number } }>(
      `/orgs/${enc(org)}/memberships/${enc(username)}`,
    );
    return m ? `${m.user?.id ?? "?"}:${m.role}:${m.state}` : undefined;
  }

  /**
   * Team: id, node_id, `updated_at` and a hash of its
   * name / description / privacy / permission / parent. Member and repo counts are excluded (volatile),
   * so a membership change during the prompt is NOT detected.
   */
  async teamVersion(org: string, slug: string): Promise<string | undefined> {
    const t = await this.getOrUndefined<Record<string, unknown> & { id: number; node_id: string; updated_at?: string; parent?: { id?: number } | null }>(
      `/orgs/${enc(org)}/teams/${enc(slug)}`,
    );
    if (!t) return undefined;
    const content = digest({ name: t.name, description: t.description, privacy: t.privacy, permission: t.permission, parent: t.parent?.id ?? null });
    return `${t.id}:${t.node_id}:${t.updated_at ?? "-"}:${content}`;
  }

  /**
   * Org ruleset: id, `updated_at` and a hash of its name, target, enforcement, conditions and rules, so
   * the human approves the protection as it currently reads. Bypass actors are not part of the hash.
   */
  async rulesetVersion(org: string, id: number): Promise<string | undefined> {
    const r = await this.getOrUndefined<Record<string, unknown> & { id: number; updated_at?: string }>(`/orgs/${enc(org)}/rulesets/${id}`);
    if (!r) return undefined;
    const content = digest({ name: r.name, target: r.target, enforcement: r.enforcement, conditions: r.conditions, rules: r.rules });
    return `${r.id}:${r.updated_at ?? "-"}:${content}`;
  }

  /**
   * Org webhook: id, `updated_at` and a hash of its payload URL, events and active flag. The signing
   * secret is never read or hashed (GitHub masks it in responses anyway).
   */
  async webhookVersion(org: string, id: number): Promise<string | undefined> {
    const h = await this.getOrUndefined<{ id: number; updated_at?: string; active?: boolean; events?: string[]; config?: { url?: string; content_type?: string } }>(
      `/orgs/${enc(org)}/hooks/${id}`,
    );
    if (!h) return undefined;
    const content = digest({ active: h.active, events: [...(h.events ?? [])].sort(), url: h.config?.url, contentType: h.config?.content_type });
    return `${h.id}:${h.updated_at ?? "-"}:${content}`;
  }

  /**
   * The org's webhook set (id, url, events, active per hook; secrets excluded). Pinned for create_webhook,
   * which has no existing object to version: it refuses if a webhook was added, removed or edited while the
   * human was reading the prompt. Reads at most GHE_MAX_PAGES pages; it does not pin the org's identity itself.
   */
  async webhookSetVersion(org: string): Promise<string | undefined> {
    const hooks = await this.paginate<{ id: number; active?: boolean; events?: string[]; config?: { url?: string } }>(`/orgs/${enc(org)}/hooks`);
    const rows = hooks.map((h) => `${h.id}:${digest({ a: h.active, e: [...(h.events ?? [])].sort(), u: h.config?.url })}`).sort();
    return digest(rows);
  }

  /**
   * The org settings that `harden_org_settings` is about to overwrite: org id + node_id and the CURRENT
   * value of exactly the keys the action will write. Detects someone else changing those settings during
   * the prompt; changes to other org fields are intentionally ignored.
   */
  async orgSettingsVersion(org: string, keys: string[]): Promise<string | undefined> {
    const o = await this.getOrUndefined<Record<string, unknown> & { id: number; node_id: string }>(`/orgs/${enc(org)}`);
    if (!o) return undefined;
    const current: Record<string, unknown> = {};
    for (const k of [...keys].sort()) current[k] = o[k] ?? null;
    return `${o.id}:${o.node_id}:${digest(current)}`;
  }

  private async getOrUndefined<T>(path: string): Promise<T | undefined> {
    try {
      return await this.request<T>("GET", path);
    } catch (err) {
      if (err instanceof GithubError && err.status === 404) return undefined;
      throw err;
    }
  }
}

/** Short sha256 over a key-order-independent JSON rendering. */
function digest(value: unknown): string {
  return createHash("sha256").update(canonical(value)).digest("hex").slice(0, 12);
}

function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value && typeof value === "object") {
    const o = value as Record<string, unknown>;
    return `{${Object.keys(o).sort().filter((k) => o[k] !== undefined).map((k) => `${JSON.stringify(k)}:${canonical(o[k])}`).join(",")}}`;
  }
  return JSON.stringify(value ?? null);
}

function enc(s: string): string {
  return encodeURIComponent(s);
}

/** Pull the `rel="next"` URL out of a Link header, or null when there is none. */
function parseNextLink(link: string | null): URL | null {
  if (!link) return null;
  for (const part of link.split(",")) {
    const m = part.match(/<([^>]+)>\s*;\s*rel="next"/);
    if (m) return new URL(m[1]);
  }
  return null;
}
