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
