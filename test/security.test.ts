import { describe, expect, it } from "vitest";
import { SecurityPolicy, type SecurityConfig } from "../src/security.js";

function makePolicy(overrides: Partial<SecurityConfig> = {}): SecurityPolicy {
  return new SecurityPolicy({
    mode: "read-only",
    orgAllowlist: [],
    protectedOrgs: [],
    allowDelete: false,
    requireConfirmation: true,
    dryRun: false,
    auditLog: false,
    ...overrides,
  });
}

describe("capability gating", () => {
  it("read-only enables read only", () => {
    const p = makePolicy();
    expect(p.isCapabilityEnabled("read")).toBe(true);
    expect(p.isCapabilityEnabled("write")).toBe(false);
    expect(p.isCapabilityEnabled("admin")).toBe(false);
  });
  it("read-write enables read + write but not admin", () => {
    const p = makePolicy({ mode: "read-write" });
    expect(p.isCapabilityEnabled("write")).toBe(true);
    expect(p.isCapabilityEnabled("admin")).toBe(false);
  });
});

describe("org allowlist + protection", () => {
  it("blocks orgs outside a non-empty allowlist (case-insensitive)", () => {
    const p = makePolicy({ mode: "read-write", orgAllowlist: ["Acme"] });
    expect(() => p.guard({ tool: "list_repositories", capability: "read", org: "other" })).toThrow(/allowlist/);
    expect(() => p.guard({ tool: "list_repositories", capability: "read", org: "acme" })).not.toThrow();
  });
  it("allows reading a protected org but not mutating it", () => {
    const p = makePolicy({ mode: "admin", allowDelete: true, protectedOrgs: ["platform"] });
    expect(() => p.guard({ tool: "get_organization", capability: "read", org: "platform" })).not.toThrow();
    expect(() => p.guard({ tool: "harden_org_settings", capability: "write", org: "platform" })).toThrow(/protected/);
  });
});

describe("destructive gating", () => {
  it("blocks delete without allowDelete", () => {
    const p = makePolicy({ mode: "admin" });
    expect(() =>
      p.guard({ tool: "delete_repository", capability: "admin", org: "o", destructive: true, confirmExpected: "o/r", confirmProvided: "o/r" }),
    ).toThrow(/ALLOW_DELETE/);
  });
});

describe("high-impact confirmation", () => {
  it("refuses when the typed confirmation does not match", () => {
    const p = makePolicy({ mode: "admin", allowDelete: true });
    expect(() =>
      p.guard({ tool: "delete_repository", capability: "admin", org: "o", destructive: true, confirmExpected: "o/prod", confirmProvided: "o/Prod" }),
    ).toThrow(/confirm="o\/prod"/);
  });
  it("proceeds when the confirmation matches", () => {
    const p = makePolicy({ mode: "admin", allowDelete: true });
    expect(() =>
      p.guard({ tool: "delete_repository", capability: "admin", org: "o", destructive: true, confirmExpected: "o/prod", confirmProvided: "o/prod" }),
    ).not.toThrow();
  });
  it("can be disabled via requireConfirmation=false", () => {
    const p = makePolicy({ mode: "admin", allowDelete: true, requireConfirmation: false });
    expect(() =>
      p.guard({ tool: "delete_repository", capability: "admin", org: "o", destructive: true, confirmExpected: "o/prod", confirmProvided: undefined }),
    ).not.toThrow();
  });
});

describe("dry run", () => {
  it("flags writes but not reads", () => {
    const p = makePolicy({ mode: "read-write", dryRun: true });
    expect(p.guard({ tool: "get_organization", capability: "read", org: "o" }).dryRun).toBe(false);
    expect(p.guard({ tool: "harden_org_settings", capability: "write", org: "o" }).dryRun).toBe(true);
  });
});
