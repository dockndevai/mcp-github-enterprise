/**
 * Governance & security policy engine.
 *
 * On top of the shared suite model (access modes + capability gating + allowlists +
 * protected resources + delete gating + dry-run + audit), this server scopes by the
 * natural GitHub Enterprise unit — the **organization**:
 *   - Org scoping: an allowlist of orgs, plus protected orgs that can be read but
 *     never mutated (read-only forever).
 *   - High-impact confirmation: destructive operations must echo back the exact
 *     target (a typed confirmation), not just a boolean, before they run.
 *
 * Pure logic, no I/O — fully unit-testable.
 */

export type Capability = "read" | "write" | "admin";
export type AccessMode = "read-only" | "read-write" | "admin";

const MODE_RANK: Record<AccessMode, number> = { "read-only": 0, "read-write": 1, admin: 2 };
const CAPABILITY_RANK: Record<Capability, number> = { read: 0, write: 1, admin: 2 };

export interface SecurityConfig {
  mode: AccessMode;
  /** If set, only these organizations may be touched. Empty = all visible. */
  orgAllowlist: string[];
  /** Organizations that can be read but never mutated or deleted. */
  protectedOrgs: string[];
  /** Destructive delete/remove operations require this. */
  allowDelete: boolean;
  /** High-impact (destructive) operations require a typed confirmation match. */
  requireConfirmation: boolean;
  /** Validate + log writes without sending them to GitHub. */
  dryRun: boolean;
  auditLog: boolean;
}

export class PolicyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PolicyError";
  }
}

export interface GuardContext {
  tool: string;
  capability: Capability;
  /** Organization the operation targets, if any. Compared case-insensitively. */
  org?: string;
  /** Destructive delete/remove operation — needs allowDelete. */
  destructive?: boolean;
  /** For high-impact ops: the exact value the caller must type to confirm. */
  confirmExpected?: string;
  /** The confirmation the caller actually provided. */
  confirmProvided?: string;
}

export class SecurityPolicy {
  constructor(private readonly config: SecurityConfig) {}

  get mode(): AccessMode {
    return this.config.mode;
  }

  isCapabilityEnabled(capability: Capability): boolean {
    return CAPABILITY_RANK[capability] <= MODE_RANK[this.config.mode];
  }

  isOrgAllowed(org: string): boolean {
    if (this.config.orgAllowlist.length === 0) return true;
    return this.config.orgAllowlist.some((o) => o.toLowerCase() === org.toLowerCase());
  }

  isOrgProtected(org: string): boolean {
    return this.config.protectedOrgs.some((o) => o.toLowerCase() === org.toLowerCase());
  }

  guard(ctx: GuardContext): { dryRun: boolean } {
    if (!this.isCapabilityEnabled(ctx.capability)) {
      this.audit(ctx, "DENY", `capability '${ctx.capability}' exceeds mode '${this.config.mode}'`);
      throw new PolicyError(
        `Operation '${ctx.tool}' requires '${ctx.capability}' access but the server runs in '${this.config.mode}' mode.`,
      );
    }

    if (ctx.org !== undefined) {
      if (!this.isOrgAllowed(ctx.org)) {
        this.audit(ctx, "DENY", `org '${ctx.org}' not in allowlist`);
        throw new PolicyError(
          `Organization '${ctx.org}' is not in the configured allowlist (GHE_ORG_ALLOWLIST).`,
        );
      }
      if (ctx.capability !== "read" && this.isOrgProtected(ctx.org)) {
        this.audit(ctx, "DENY", `org '${ctx.org}' is protected`);
        throw new PolicyError(
          `Organization '${ctx.org}' is protected (GHE_PROTECTED_ORGS); mutations are refused.`,
        );
      }
    }

    if (ctx.destructive && !this.config.allowDelete) {
      this.audit(ctx, "DENY", "delete not enabled");
      throw new PolicyError(
        `Destructive operation '${ctx.tool}' is disabled. Set GHE_ALLOW_DELETE=true to enable it.`,
      );
    }

    // Governance: typed confirmation for high-impact operations.
    if (ctx.destructive && this.config.requireConfirmation && ctx.confirmExpected !== undefined) {
      if (ctx.confirmProvided !== ctx.confirmExpected) {
        this.audit(ctx, "DENY", "confirmation mismatch");
        throw new PolicyError(
          `Operation '${ctx.tool}' is high-impact. Re-run with confirm="${ctx.confirmExpected}" to proceed.`,
        );
      }
    }

    const dryRun = ctx.capability !== "read" && this.config.dryRun;
    this.audit(ctx, dryRun ? "DRY_RUN" : "ALLOW");
    return { dryRun };
  }

  private audit(ctx: GuardContext, decision: string, reason?: string): void {
    if (!this.config.auditLog) return;
    const line = {
      ts: new Date().toISOString(),
      audit: "github-enterprise-mcp",
      decision,
      tool: ctx.tool,
      capability: ctx.capability,
      org: ctx.org ?? null,
      destructive: ctx.destructive ?? false,
      ...(reason ? { reason } : {}),
    };
    process.stderr.write(`${JSON.stringify(line)}\n`);
  }
}
