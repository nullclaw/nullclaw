# Parallel Search MCP

Add web search and page extraction with NullClaw's built-in HTTP MCP transport.
[Parallel Search MCP](https://docs.parallel.ai/integrations/mcp/search-mcp) supports
anonymous free access for exploration and light use, with rate limits. No Parallel
API key, local MCP bridge, or additional package is needed.

## Setup

1. Install NullClaw using the [installation guide](../../docs/en/installation.md).
   For a source build, install the pinned [Zig 0.16.0 toolchain](../../docs/en/zig-installation.md)
   and run `zig build` from the repository root. The binary is `zig-out/bin/nullclaw`.
2. Configure your model with `nullclaw onboard` if you have not already done so.
3. Merge the `parallel` entry from [config.json](config.json) into the top-level
   `mcp_servers` object in `~/.nullclaw/config.json`. Create that object if absent.
   Keep your existing model, other servers, and security settings. This file is a
   configuration fragment, not a replacement for your complete config.
4. Restart any running NullClaw agent or gateway to load the server.

The configuration sets a 30-second timeout per MCP request and a project
`User-Agent`. It sends no authorization header. Search queries and fetched URLs
are sent to Parallel.

## Try it

Confirm that the server configuration loads:

```bash
nullclaw mcp list
nullclaw mcp info parallel --json
```

`mcp list` inspects configuration. `mcp info` connects and discovers tools;
expect `"tool_count": 2`. A `null` count means discovery failed, so check the
endpoint, timeout, and network access. Start an agent to use the tools:

```bash
nullclaw agent -m "Use mcp_parallel_web_search to find the official Zig 0.16.0 release notes and summarize the results with source URLs."
nullclaw agent -m "Use mcp_parallel_web_fetch to read https://ziglang.org/download/0.16.0/release-notes.html and summarize the main changes."
```

NullClaw discovers `web_search` and `web_fetch` and exposes them as
`mcp_parallel_web_search` and `mcp_parallel_web_fetch`. A tool-capable configured
model chooses the calls; inspect the agent output for source URLs and excerpts.
These optional MCP tools leave the built-in search tool and its provider unchanged.

If the tools are missing, check startup messages for MCP connection or discovery
errors and verify outbound HTTPS access to `search.parallel.ai`. A request timeout
may need a larger `timeout_ms`. If the free endpoint reports a rate limit, wait
for the indicated retry interval.

中文说明见[配置指南](../../docs/zh/configuration.md#parallel-search-mcp)。
