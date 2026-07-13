# PR: Structured streaming tool-call support for SSE parser (companion to root fix)

## Problem

The root fix (`agent/root.zig` native-tools-in-streaming) enables `tools[]` + `tool_choice: "auto"` in streaming requests. For servers that leave model-emitted XML in `delta.content`, this is sufficient — the agent parses `<tool_call>` from the accumulated text.

However, vLLM deployments with `--enable-auto-tool-choice --tool-call-parser` ([vLLM docs](https://docs.vllm.ai/en/latest/features/tool_calling.html)) intercept the model's XML output, strip it from `delta.content`, and re-emit it as structured `delta.tool_calls` in the SSE stream. The current SSE parser (`src/providers/sse.zig`) only reads `delta.content` and `delta.reasoning*` — it ignores `delta.tool_calls`, producing `NoResponseContent` when the server-side parser is active.

## Design

`MultiToolCallAccumulator` accumulates `delta.tool_calls` by `index` field (supporting multiple parallel tool calls per the [OpenAI streaming spec](https://platform.openai.com/docs/guides/function-calling#streaming)). Returns structured `ToolCall[]` through `StreamChatResult` — no XML conversion, no user-visible markup.

## Changes

### `src/providers/root.zig` — 1 field added

Add `tool_calls` to `StreamChatResult`:
```zig
pub const StreamChatResult = struct {
    content: ?[]const u8 = null,
    reasoning_content: ?[]const u8 = null,
    tool_calls: ?[]const ToolCall = null,  // NEW
    usage: TokenUsage = .{},
    model: []const u8 = "",
};
```

Update `emitChatResponseAsStream` to steal `response.tool_calls` before `freeStreamUnusedChatResponseFields` frees them.

### `src/providers/sse.zig` — ~200 lines added

**New types and functions:**

- `MultiToolCallAccumulator` — array of `DisassembledToolCall` keyed by `index`. Supports N parallel tool calls.
  - `ensureIndex()` — finds or creates a slot for a given index
  - `intoOwnedToolCalls()` — converts to `[]ToolCall` with stable fallback IDs (`call_{index}`)
- `extractSseDataPayload()` — strips `data:` SSE framing, returns JSON payload
- `extractToolCallDelta()` — parses `delta.tool_calls` from a JSON payload, accumulates into `MultiToolCallAccumulator`
- `isToolCallFinishReason()` — returns `true` if the chunk has `finish_reason: "tool_calls"` (no dangling pointer)
- `finalizeStreamResultWithToolCalls()` — wrapper called from all 4 return sites in `curlStream()` to attach accumulated tool calls

**Changes to `curlStream()`:**

1. Add accumulator declarations beside existing stream state
2. Extract `sse_data` via `extractSseDataPayload()` before `parseSseLine()` — runs tool-call extraction on EVERY chunk, not only `.skip` branches (catches chunks with both `delta.content` and `delta.tool_calls`)
3. Apply same extraction to the trailing-line-without-newline path
4. Replace every `return finalizeStreamResult(...)` with `return finalizeStreamResultWithToolCalls(...)` — covers normal completion, wait failure recovery, nonzero exit recovery, and abnormal termination recovery

**Removed (not needed):**
- `formatToolCallXml` — no XML conversion
- `flushToolCalls` — no user-visible markup
- `extractFinishReason` — replaced by `isToolCallFinishReason` bool

### `src/agent/root.zig` — 1 line

At line 2293, wire streaming tool calls through:
```zig
// Before:
.tool_calls = &.{},
// After:
.tool_calls = stream_result.tool_calls orelse &.{},
```

## Testing

Add SSE fixture tests for:
- Chunked `delta.tool_calls` across multiple chunks (single call)
- Two parallel tool calls with different `index` values (0 and 1)
- A single chunk carrying both `delta.content` and `delta.tool_calls`
- Trailing line without final `\n` containing tool-call data

## Prior art

- [OpenAI streaming function calls](https://platform.openai.com/docs/guides/function-calling#streaming): `delta.tool_calls` with index, id, function name, and chunked arguments
- [vLLM auto tool choice](https://docs.vllm.ai/en/latest/features/tool_calling.html): server-side parser strips XML, emits structured `delta.tool_calls`
