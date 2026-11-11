import { createRequire } from "node:module";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { AppConfig } from "./config.js";
import { GithubClient, GithubError } from "./github/client.js";
import { canonicalArgs, makeConfirmer } from "./elicit.js";
import { GuardClient, loadGuardConfig } from "./guard.js";
import { PolicyError, SecurityPolicy } from "./security.js";
import { adminTools } from "./tools/admin.js";
import { readTools } from "./tools/read.js";
import { annotationsFor } from "./tools/annotations.js";
import type { ToolContext, ToolDef } from "./tools/types.js";
import { writeTools } from "./tools/write.js";

/**
 * The version is read from package.json at runtime so it can never drift from the published package.
 * `../package.json` resolves from both `src/` (tsx, vitest) and `dist/` (the built server): `package.json`
 * is always part of the npm tarball and is copied into the Docker image by `COPY . .`.
 */
export const SERVER_VERSION: string = (createRequire(import.meta.url)("../package.json") as { version: string }).version;

export const ALL_TOOLS: ToolDef[] = [...readTools, ...writeTools, ...adminTools];

export function buildServer(config: AppConfig): { server: McpServer; enabled: string[] } {
  const policy = new SecurityPolicy(config.security);
  const client = new GithubClient(config.connection);
  const server = new McpServer({ name: "mcp-github-enterprise", version: SERVER_VERSION });
  const guard = new GuardClient(loadGuardConfig());
  const confirmer = makeConfirmer(server, {
    name: "mcp-github-enterprise",
    requireHuman: config.security.requireHumanApproval,
    audit: config.security.auditLog,
  });
  const ctx: ToolContext = { client, policy, confirm: confirmer, guard };

  const enabled: string[] = [];
  for (const tool of ALL_TOOLS) {
    if (!policy.isCapabilityEnabled(tool.capability)) continue;
    enabled.push(tool.name);
    server.registerTool(tool.name, { ...tool.config, annotations: annotationsFor(tool) }, async (args: Record<string, unknown>) => {
      try {
        // Every approval prompt in this call is bound to this tool + these exact arguments.
        const callCtx: ToolContext = { ...ctx, confirm: confirmer.forCall(tool.name, args ?? {}) };
        // laya-guard: assess every mutating op before it runs (no-op unless GHE_GUARD_MODE is set).
        if (tool.capability !== "read") {
          await guard.enforce({ tool: tool.name, command: `${tool.name} ${canonicalArgs(args ?? {})}`, context: tool.name }, callCtx.confirm);
        }
        return await tool.handler(args ?? {}, callCtx);
      } catch (err) {
        return toErrorResult(err);
      }
    });
  }
  return { server, enabled };
}

function toErrorResult(err: unknown) {
  let message: string;
  if (err instanceof PolicyError) message = `Policy denied: ${err.message}`;
  else if (err instanceof GithubError)
    message = `GitHub error (${err.status}): ${err.message}${err.rateLimitRemaining !== undefined ? ` [rate-limit remaining: ${err.rateLimitRemaining}]` : ""}${err.body ? `\n${truncate(err.body)}` : ""}`;
  else if (err instanceof Error) message = `${err.name}: ${err.message}`;
  else message = String(err);
  return { content: [{ type: "text" as const, text: message }], isError: true };
}

function truncate(s: string, max = 800): string {
  return s.length > max ? `${s.slice(0, max)}…` : s;
}
