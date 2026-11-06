import type { AccessMode, SecurityConfig } from "./security.js";

export interface GithubConnection {
  /** API base URL. Cloud: https://api.github.com. GHES: https://HOST/api/v3. */
  apiUrl: string;
  /** Token: fine-grained PAT, classic PAT, or App installation token. */
  token: string;
  /** Enterprise slug for enterprise-level endpoints (optional). */
  enterprise: string;
  requestTimeout: number;
  /** Safety cap on auto-pagination (pages of 100). */
  maxPages: number;
}

export interface AppConfig {
  connection: GithubConnection;
  security: SecurityConfig;
}

function bool(name: string, fallback: boolean): boolean {
  const v = process.env[name];
  if (v === undefined || v === "") return fallback;
  return ["1", "true", "yes", "on"].includes(v.toLowerCase());
}

function list(name: string): string[] {
  const v = process.env[name];
  if (!v) return [];
  return v.split(",").map((s) => s.trim()).filter(Boolean);
}

function parseMode(): AccessMode {
  const raw = (process.env.GHE_MODE ?? "read-only").toLowerCase();
  if (raw === "read-only" || raw === "read-write" || raw === "admin") return raw;
  throw new Error(`Invalid GHE_MODE '${raw}'. Expected one of: read-only, read-write, admin.`);
}

export function loadConfig(): AppConfig {
  // Fall back to placeholders so the server can start and advertise its tools
  // (introspection); API calls fail only when a tool is actually invoked.
  const apiUrl = (process.env.GHE_API_URL || "https://api.github.com").replace(/\/+$/, "");
  const token = process.env.GHE_TOKEN ?? "";
  if (!token) {
    process.stderr.write("[github-enterprise-mcp] WARNING: GHE_TOKEN not set; tool calls will fail until provided.\n");
  }
  return {
    connection: {
      apiUrl,
      token,
      enterprise: (process.env.GHE_ENTERPRISE ?? "").trim(),
      requestTimeout: Number(process.env.GHE_TIMEOUT_MS ?? 20000),
      maxPages: Math.max(1, Number(process.env.GHE_MAX_PAGES ?? 10)),
    },
    security: {
      mode: parseMode(),
      orgAllowlist: list("GHE_ORG_ALLOWLIST"),
      protectedOrgs: list("GHE_PROTECTED_ORGS"),
      allowDelete: bool("GHE_ALLOW_DELETE", false),
      requireConfirmation: bool("GHE_REQUIRE_CONFIRMATION", true),
      dryRun: bool("GHE_DRY_RUN", false),
      auditLog: bool("GHE_AUDIT_LOG", true),
    },
  };
}
