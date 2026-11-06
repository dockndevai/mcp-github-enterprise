# Installing `@dockndevai/mcp-github-enterprise` in your MCP client

A **stdio** MCP server. Published on npm — your MCP client runs it with `npx` (no clone needed), or run from a local build. **Start in `read-only` mode.** See [`.env.example`](../.env.example) for every variable.

> GitHub Enterprise **Server (GHES)**: set `GHE_API_URL=https://HOST/api/v3`. **Cloud**: omit it (defaults to `https://api.github.com`).

## Claude Code (CLI)

```bash
claude mcp add github-enterprise -e GHE_TOKEN="your-token" -e GHE_MODE="read-only" -- npx -y @dockndevai/mcp-github-enterprise
```

## Claude Desktop · Cursor · Windsurf

Merge into `claude_desktop_config.json`, `.cursor/mcp.json`, or `~/.codeium/windsurf/mcp_config.json`:

```json
{
  "mcpServers": {
    "github-enterprise": {
      "command": "npx",
      "args": [
        "-y",
        "@dockndevai/mcp-github-enterprise"
      ],
      "env": {
        "GHE_TOKEN": "your-token",
        "GHE_MODE": "read-only",
        "GHE_ORG_ALLOWLIST": "your-org"
      }
    }
  }
}
```

## OpenAI Codex CLI (`~/.codex/config.toml`)

```toml
[mcp_servers.github-enterprise]
command = "npx"
args = ["-y", "@dockndevai/mcp-github-enterprise"]
env = { GHE_TOKEN = "your-token", GHE_MODE = "read-only", GHE_ORG_ALLOWLIST = "your-org" }
```

## VS Code (GitHub Copilot, Agent mode) — `.vscode/mcp.json`

```json
{
  "servers": {
    "github-enterprise": {
      "type": "stdio",
      "command": "npx",
      "args": [
        "-y",
        "@dockndevai/mcp-github-enterprise"
      ],
      "env": {
        "GHE_TOKEN": "your-token",
        "GHE_MODE": "read-only",
        "GHE_ORG_ALLOWLIST": "your-org"
      }
    }
  }
}
```

## From a local build

```json
{
  "mcpServers": {
    "github-enterprise": {
      "command": "node",
      "args": [
        "/ABSOLUTE/PATH/TO/mcp-github-enterprise/dist/index.js"
      ],
      "env": {
        "GHE_TOKEN": "your-token",
        "GHE_MODE": "read-only",
        "GHE_ORG_ALLOWLIST": "your-org"
      }
    }
  }
}
```

## Verify

On startup the server logs to **stderr**: `[github-enterprise-mcp] Starting in 'read-only' mode against https://api.github.com. N tools enabled: …`. Ask your agent to run `whoami` to confirm the token and base URL are wired correctly.
