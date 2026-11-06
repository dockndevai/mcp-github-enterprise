import { describe, expect, it } from "vitest";
import { assessPosture, summarize, ORG_SECURITY_BASELINE, type OrgSettings } from "../src/baseline.js";

const HARDENED: OrgSettings = {
  two_factor_requirement_enabled: true,
  default_repository_permission: "read",
  members_can_create_public_repositories: false,
  members_can_fork_private_repositories: false,
  web_commit_signoff_required: true,
  secret_scanning_enabled_for_new_repositories: true,
  secret_scanning_push_protection_enabled_for_new_repositories: true,
  dependabot_alerts_enabled_for_new_repositories: true,
  dependabot_security_updates_enabled_for_new_repositories: true,
  dependency_graph_enabled_for_new_repositories: true,
};

const WIDE_OPEN: OrgSettings = {
  two_factor_requirement_enabled: false,
  default_repository_permission: "write",
  members_can_create_public_repositories: true,
  members_can_fork_private_repositories: true,
  web_commit_signoff_required: false,
  secret_scanning_enabled_for_new_repositories: false,
  secret_scanning_push_protection_enabled_for_new_repositories: false,
  dependabot_alerts_enabled_for_new_repositories: false,
  dependabot_security_updates_enabled_for_new_repositories: false,
  dependency_graph_enabled_for_new_repositories: false,
};

describe("assessPosture", () => {
  it("passes every control on a fully hardened org", () => {
    const findings = assessPosture(HARDENED, { allowed_actions: "selected", enabled_repositories: "selected" });
    expect(findings.every((f) => f.status === "pass")).toBe(true);
    const s = summarize(findings);
    expect(s.score).toBe(100);
    expect(s.grade).toBe("A");
    expect(s.high_failures).toBe(0);
  });

  it("fails the high-severity controls on a wide-open org", () => {
    const findings = assessPosture(WIDE_OPEN, { allowed_actions: "all", enabled_repositories: "all" });
    const twofa = findings.find((f) => f.id === "two-factor")!;
    const push = findings.find((f) => f.id === "push-protection")!;
    expect(twofa.status).toBe("fail");
    expect(twofa.severity).toBe("high");
    expect(push.status).toBe("fail");
    const s = summarize(findings);
    expect(s.score).toBeLessThan(40);
    expect(s.grade).toBe("F");
    expect(s.high_failures).toBeGreaterThanOrEqual(2);
  });

  it("marks missing fields as unknown, not fail", () => {
    const findings = assessPosture({}, undefined);
    expect(findings.every((f) => f.status === "unknown")).toBe(true);
    // actions checks are skipped entirely when no actions permissions are supplied
    expect(findings.some((f) => f.id.startsWith("actions-"))).toBe(false);
  });

  it("every failing finding names a concrete remediation", () => {
    const findings = assessPosture(WIDE_OPEN);
    for (const f of findings.filter((x) => x.status === "fail")) {
      expect(f.remediation.length).toBeGreaterThan(0);
    }
  });
});

describe("baseline body", () => {
  it("only recommends safe values", () => {
    expect(ORG_SECURITY_BASELINE.default_repository_permission).toBe("read");
    expect(ORG_SECURITY_BASELINE.secret_scanning_push_protection_enabled_for_new_repositories).toBe(true);
    expect(ORG_SECURITY_BASELINE.members_can_create_public_repositories).toBe(false);
  });
});
