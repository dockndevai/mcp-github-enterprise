import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import type { AppConfig } from "../src/config.js";
import { buildServer, SERVER_VERSION } from "../src/server.js";

const read = (f: string) => JSON.parse(readFileSync(new URL(`../${f}`, import.meta.url), "utf8"));

describe("version consistency", () => {
  const pkg = read("package.json");

  it("the version the server advertises over MCP equals package.json", async () => {
    const config: AppConfig = {
      connection: { apiUrl: "https://api.github.com", token: "t", enterprise: "", requestTimeout: 1000, maxPages: 1 },
      security: {
        mode: "read-only",
        orgAllowlist: [],
        protectedOrgs: [],
        allowDelete: false,
        requireConfirmation: true,
        dryRun: false,
        auditLog: false,
        requireHumanApproval: false,
      },
    };
    const { server } = buildServer(config);
    const client = new Client({ name: "t", version: "0" });
    const [a, b] = InMemoryTransport.createLinkedPair();
    await Promise.all([server.connect(a), client.connect(b)]);
    expect(client.getServerVersion()?.version).toBe(pkg.version);
    expect(SERVER_VERSION).toBe(pkg.version);
  });

  it("server.json (top-level and the npm package entry) and package-lock.json equal package.json", () => {
    const manifest = read("server.json");
    expect(manifest.version).toBe(pkg.version);
    for (const p of manifest.packages) expect(p.version).toBe(pkg.version);
    const lock = read("package-lock.json");
    expect(lock.version).toBe(pkg.version);
    expect(lock.packages[""].version).toBe(pkg.version);
  });

  it("the server source does not hard-code a version literal", () => {
    expect(readFileSync(new URL("../src/server.ts", import.meta.url), "utf8")).not.toMatch(/version:\s*"\d/);
  });
});
