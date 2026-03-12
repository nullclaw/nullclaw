# Architecture

NullClaw uses a vtable-driven pluggable architecture. Most capabilities are extended by implementing interfaces and registering factories.

## Page Guide

**Who this page is for**

- Contributors learning the main subsystem boundaries before editing code
- Reviewers checking whether a change follows the vtable and factory extension model
- Integrators deciding where a new provider, channel, tool, memory backend, or runtime fits

**Read this next**

- Open [Development](./development.md) before making repo changes or running contributor validation flows
- Open [Security](./security.md) if your design touches gateway, sandbox, tools, or exposure boundaries
- Open [README](./README.md) if you need the broader English docs map around this contributor-focused view

**If you came from ...**

- [Development](./development.md): this page gives the subsystem map behind the contributor workflow
- [README](./README.md): this is the deeper design path once you know you need implementation-level context
- `AGENTS.md`: use this page to connect repo guardrails with the concrete module layout and extension seams

## Core Design

- Subsystems are abstracted via interfaces using `ptr: *anyopaque + vtable`.
- Runtime implementation is selected through factories.
- Provider/channel/tool/memory swaps should not require core orchestration rewrites.

## Subsystems and Extension Points

| Subsystem | Interface | Built-in implementations (partial) | Extension approach |
|---|---|---|---|
| AI Models | `Provider` | OpenRouter, Anthropic, OpenAI, Ollama, Groq, and more | Add provider implementation + register |
| Channels | `Channel` | CLI, Telegram, Signal, Discord, Slack, Matrix, WhatsApp, Nostr, and more | Add channel implementation + register |
| Memory | `Memory` | SQLite (hybrid retrieval), Markdown | Add memory backend |
| Tools | `Tool` | shell, file_read, file_write, http_request, browser_open, and more | Add tool implementation |
| Observability | `Observer` | Noop, Log, File, Multi | Add observer backend |
| Runtime | `RuntimeAdapter` | Native, Docker, WASM | Add runtime adapter |
| Security | `Sandbox` | Landlock, Firejail, Bubblewrap, Docker(auto) | Add sandbox backend |
| Tunnel | `Tunnel` | None, Cloudflare, Tailscale, ngrok, Custom | Add tunnel provider |
| Peripheral | `Peripheral` | Serial, Arduino, RPi GPIO, STM32/Nucleo | Add hardware driver |

## Memory Stack

| Layer | Implementation |
|---|---|
| Vector retrieval | Embeddings as BLOB in SQLite, cosine similarity search |
| Keyword retrieval | SQLite FTS5 with BM25 |
| Hybrid merge | Weighted vector + keyword merge |
| Embeddings | `EmbeddingProvider` vtable (OpenAI/custom/noop) |
| Data hygiene | Automatic archive and purge |
| Snapshots | Full export/import migration path |

## Practical Constraints

1. Prefer extension through implementations, not invasive core rewrites.
2. Keep subsystem boundaries strict (avoid cross-subsystem internals coupling).
3. For high-risk paths (`security/runtime/gateway/tools`), include boundary/failure-path validation.

## Next Steps

- Read [Development](./development.md) for contributor workflow, validation expectations, and PR prep
- Review [Security](./security.md) before changing any high-risk subsystem named on this page
- Return to [README](./README.md) if you want the broader docs map after this design overview

## Related Pages

- [README](./README.md)
- [Development](./development.md)
- [Security](./security.md)
- [Commands](./commands.md)
