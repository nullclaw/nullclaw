# 設定指南

NullClaw 與 OpenClaw 設定結構相容，使用 `snake_case`（蛇形命名法）欄位名稱。

## 頁面導覽

**本頁適合誰**

- 建立或編輯主設定檔 `config.json` 的使用者
- 調整通訊頻道、閘道行為與自主執行上限的維運人員
- 將現有 OpenClaw 設定遷移映射至 NullClaw 的移轉人員

**閱讀完後下一步**

- 修改設定檔後，請參閱 [使用與維運](./usage.md) 驗證執行階段行為
- 在放寬權限、對外公開暴露或擴大工具範圍前，請先閱讀 [安全機制](./security.md)
- 若設定修改影響到配對、Webhook 或外部整合，請參閱 [Gateway API](./gateway-api.md)
- 若需要串接非核心內建的通訊頻道，請參閱 [外部頻道外掛](./external-channels.md)

**如果您是從以下位置跳轉過來**

- [安裝指南](./installation.md)：`nullclaw` 安裝完成後，本頁接續引導進行首次設定
- [首頁](./README.md)：這是選定維運/使用者文件路線後的詳細設定路徑
- [Gateway API](./gateway-api.md)：當 API 工作流程需要具體的 `gateway` 或頻道設定鍵時，請返回本頁查閱

## 設定檔路徑

- macOS/Linux：`~/.nullclaw/config.json`
- Windows：`%USERPROFILE%\.nullclaw\config.json`

建議首次起步指令：

```bash
nullclaw onboard --interactive
```

此指令會自動產生您的初始設定檔。

## 最小可執行設定

以下範例足以在本地端跑通 CLI 模式（請替換 API 金鑰）：

```json
{
  "models": {
    "providers": {
      "openrouter": {
        "api_key": "YOUR_OPENROUTER_API_KEY"
      }
    }
  },
  "agents": {
    "defaults": {
      "model": {
        "primary": "openrouter/anthropic/claude-sonnet-4"
      }
    }
  },
  "channels": {
    "cli": true
  },
  "memory": {
    "backend": "sqlite",
    "auto_save": true
  },
  "gateway": {
    "host": "127.0.0.1",
    "port": 3000,
    "require_pairing": true
  },
  "autonomy": {
    "level": "supervised",
    "workspace_only": true,
    "max_actions_per_hour": 20
  },
  "security": {
    "sandbox": {
      "backend": "auto"
    },
    "audit": {
      "enabled": true
    }
  }
}
```

## 核心設定區塊

### `diagnostics` 診斷與可觀測性

- 控制執行階段診斷與可觀測性輸出。
- 設定 OpenTelemetry 時，請使用巢狀的 `diagnostics.otel` 物件。
- OTEL spans 會在回合完成、Agent 關閉等自然運作邊界進行清除發送（Flush），對於較長的工作流程仍保留批次 Flush 作為兜底保障。
- `diagnostics.otel.endpoint` 連接遠端收集器時應使用 `https://...`。純 `http://...` 僅被允許用於 localhost/私有網路收集器，或如 `host.docker.internal`、`host.containers.internal` 及 `otel` 等單一名稱的容器內部服務。

日誌旗標（預設皆為 `false`）。`info` 等級日誌輸出至 stderr：當 `nullclaw agent` 或 `nullclaw gateway` 以前景模式執行時直接顯示在終端機中。若要寫入檔案，取決於服務包裝器或您自己的重導向設定——背景服務模式會寫入 `~/.nullclaw/logs/daemon.stderr.log`（由 launchd/systemd 服務設定提供），而 `gateway` 指令本身不會將其導向守護行程日誌檔：

- `log_tool_calls`：記錄每次工具呼叫的名稱、狀態與耗時。工具引數僅在 `log_llm_io` 同時啟用時才會記錄。
- `log_message_receipts`：記錄收到使用者訊息的事件——僅記錄元資料（頻道、連線階段雜湊、大小），絕不記錄訊息內容。
- `log_message_payloads`：記錄傳入/傳出使用者可見訊息的內容預覽——保證 UTF-8 安全且上限為 4,096 位元組，超出時標記為 `[log preview truncated]`。僅供本機除錯使用——可能包含敏感文字。
- `log_llm_io`：記錄在對話呼叫前後由 Provider 發送/回應的遮蔽與截斷內容預覽，包括回覆與推理思考（Reasoning）預覽。僅供本機除錯使用——可能包含敏感文字；在生產環境請保持關閉。
- `token_usage_ledger_enabled`（預設 `true`）搭配 `token_usage_ledger_window_hours` / `token_usage_ledger_max_bytes` / `token_usage_ledger_max_lines`：將每次回應的 Token 計數持久化記錄至 `config.json` 附近的 JSONL 總帳檔案中。僅記錄 Token 數量（Provider/Model/Prompt/Completion/Total），絕不記錄訊息本文。

生產環境安全設定範例（內容相關開關皆關閉）：

```json
{
  "diagnostics": {
    "backend": "otel",
    "log_tool_calls": true,
    "log_message_receipts": true,
    "log_message_payloads": false,
    "log_llm_io": false,
    "otel": {
      "endpoint": "https://otel.example.com:4318",
      "service_name": "nullclaw",
      "headers": {
        "Authorization": "Bearer example-token"
      }
    }
  }
}
```

### `models.providers` 模型提供商

- 定義 LLM 提供商連線參數與 API 金鑰。
- 常見提供商：`openrouter`、`openai`、`anthropic`、`groq`、`nearai`、`atlas-cloud`、`evolink`、`edenai`。

範例：

```json
{
  "models": {
    "providers": {
      "openrouter": { "api_key": "sk-or-..." },
      "nearai": { "api_key": "YOUR_NEARAI_API_KEY" },
      "atlas-cloud": { "api_key": "YOUR_ATLASCLOUD_API_KEY" },
      "edenai": { "api_key": "YOUR_EDENAI_API_KEY" },
      "evolink": { "api_key": "YOUR_EVOLINK_API_KEY" },
      "anthropic": { "api_key": "sk-ant-..." },
      "openai": { "api_key": "sk-..." }
    }
  }
}
```

每個 Provider 常用欄位：

- `api_key`：該 Provider 的認證憑證。
- `base_url`：覆寫特定的 API 端點 URL。預期的路徑格式取決於 Provider；相容 OpenAI 的提供商通常需要 `/v1` 基礎路徑，而原生 Anthropic 提供商則不需要。
- `api_mode`：針對相容提供商選擇 `chat_completions` 或 `responses`。
- `user_agent`：選填的 `User-Agent` 標頭覆寫。
- `max_streaming_prompt_bytes`：當預估提示詞超過此大小時略過串流輸出。
- `chat_template_enable_thinking_param`：針對自訂相容 OpenAI 的 vLLM/Qwen 端點，將 `reasoning_effort` 映射為 `chat_template_kwargs.enable_thinking`。

#### 原生 Anthropic 提供商

NullClaw 具備專屬的原生 Anthropic Provider，可直接連接 Anthropic API——無需透過 OpenRouter 或代理轉發。

身分驗證方式：

- **Anthropic Console API 金鑰**：透過 `x-api-key` 標頭傳送。將金鑰填入 `models.providers.anthropic.api_key` 或設定環境變數 `ANTHROPIC_API_KEY`。
- **Claude 訂閱設定 Token**（以 `sk-ant-oat01-` 開頭）：透過 Bearer 驗證傳送。可使用 `claude setup-token` 產生長效 Token，然後將其填入 `models.providers.anthropic.api_key` 或設定環境變數 `ANTHROPIC_OAUTH_TOKEN`。NullClaw 不會讀取 Claude Code 的憑證存放庫或自動更新 Token。詳情請參閱 [Claude Code 驗證指南](https://code.claude.com/docs/en/authentication#generate-a-long-lived-token)。

該提供商支援文字串流、URL 與 Base64 圖片輸入，以及非串流請求上的原生工具呼叫。設定 `reasoning_effort`（或使用 `/think`）可在支援的模型上啟用 Anthropic 延伸思考能力（Extended Thinking）。NullClaw 在 Claude Opus/Sonnet 4.6 上採用自適應思考，而在其他舊版支援模型上採用手動預算；各模型特定的 Anthropic 限制依然適用。

直接使用 Anthropic API 金鑰範例：

```json
{
  "models": {
    "providers": {
      "anthropic": { "api_key": "sk-ant-api03-..." }
    }
  },
  "agents": {
    "defaults": {
      "model": { "primary": "anthropic/claude-sonnet-4-6" }
    }
  }
}
```

注意事項：

- 在 `agents.defaults.model.primary` 中，請為 Anthropic 模型 ID 加上 `anthropic/` 前綴，例如 `anthropic/claude-sonnet-4-6`。若個別 Agent 設定中帶有獨立的 `"provider": "anthropic"` 欄位，則直接使用純模型 ID。可透過 `nullclaw --list-models --provider anthropic` 查看 NullClaw 型錄中的 Anthropic 模型清單；該指令不會檢查您的 Anthropic 帳號是否啟用了這些模型。
- `base_url` 為選填，預設為 `https://api.anthropic.com`。若使用相容 Anthropic 的代理伺服器或閘道，請將其設為 `/v1/messages` 之前的 API 根路徑（不要包含末端的 `/v1`）；NullClaw 會自動附加該路徑。遠端端點必須使用 HTTPS，純 HTTP 僅允許用於本機或私有網路主機。

### `agents.defaults.model.primary` 預設模型路由

- 設定預設模型路由，通常為 `provider/vendor/model`。
- 範例：`openrouter/anthropic/claude-sonnet-4`

### `agent.default_queue_mode` 預設佇列模式

- 設定新建立連線階段的傳入訊息佇列處理模式。接受的值為 `off`、`serial`、`latest` 與 `debounce`；預設為 `off`。
- `off`：在回合執行期間丟棄新到達的訊息；`serial`：等待進行中的回合結束後依序處理；`latest`：僅保留最新一筆待處理的插入訊息；`debounce`：採用現有的防抖處理模式（此欄位不設定其持續時間、上限或丟棄原則）。
- `/queue` 指令可覆寫當前連線階段的模式。`/queue reset`、`/restart` 與 `/debug reset` 可還原為設定檔預設值。
- 修改此設定需重啟服務，以使連線階段管理員與新連線階段採用相同的預設值。

範例：

```json
{
  "agent": {
    "default_queue_mode": "latest"
  }
}
```

### `workspace_audit.llm_triage` 工作區審計 LLM 篩檢

- 選取 `nullclaw workspace audit --llm-triage external` 所使用的 Provider/Model。
- 此設定本身不會自動啟用外部 LLM 篩檢，命令列模式仍維持主動選用（Opt-in）。
- 若省略，將回退使用 `agents.defaults.model.primary`。

範例：

```json
{
  "workspace_audit": {
    "llm_triage": {
      "provider": "ollama",
      "model": "qwen2.5-coder:7b",
      "max_calls": 20
    }
  }
}
```

當 Provider 在 `models.providers` 中已設定時，您也可以將模型指定為帶有 Provider 前綴的參照，例如 `"model": "openrouter/anthropic/claude-sonnet-4"`。

### `model_routes` 模型路由表

- 選填的最上層路由表，用於在 `nullclaw agent` 中為每個回合自動選取合適的模型。
- 每個項目將一個路由提示（`hint`）映射到特定的 `provider` 與 `model`。
- 目前守護行程辨識的路由提示為 `fast`、`balanced`、`deep`、`reasoning` 與 `vision`。
- `balanced`（均衡）：設定時的常態備用路由。`fast`（快速）：優先用於簡短的狀態/列表/檢查提示詞，以及簡短的結構化任務（如資料擷取、計數、分類或窄範圍的純轉換）。`deep`（深度）與 `reasoning`（推理）：優先用於調查、規劃、權衡分析與長上下文場景。`vision`（視覺）：用於處理圖片回合。
- `api_key` 為選填。若省略，NullClaw 會直接使用 `models.providers.<provider>` 中的常規憑證。
- `cost_class` 為選填元資料，值可為 `free`、`cheap`、`standard` 或 `premium`。
- `quota_class` 為選填元資料，值可為 `unlimited`、`normal` 或 `constrained`。

範例：

```json
{
  "model_routes": [
    { "hint": "fast", "provider": "groq", "model": "llama-3.3-70b", "cost_class": "free", "quota_class": "unlimited" },
    { "hint": "balanced", "provider": "openrouter", "model": "anthropic/claude-sonnet-4", "cost_class": "standard", "quota_class": "normal" },
    { "hint": "deep", "provider": "openrouter", "model": "anthropic/claude-opus-4", "cost_class": "premium", "quota_class": "constrained" },
    { "hint": "vision", "provider": "openrouter", "model": "openai/gpt-4.1", "cost_class": "standard", "quota_class": "normal" }
  ]
}
```

注意事項：

- `model_routes` 僅在連線階段未釘選至明確模型時生效。
- 若同時設定了 `deep` 與 `reasoning`，深度分析提示詞優先選取 `deep`。
- `/model` 會顯示上一次自動路由決策，以便維運人員了解選取了哪條路由及其原因。
- 自動路由的連線階段在遇到配額或速率限制失敗後，會暫時將該路由降級，並在冷卻時間結束前略過該路由。
- 路由元資料僅作為評分輔助。模糊不明確的提示詞依然停留在 `balanced`；`fast` 保留給高信心的便宜任務，而強烈深度分析特徵依然優先於便宜路由。

### `agents.list` Agent 設定檔清單

- 定義由 `delegate` 工具、`/subagents spawn --agent` 與 `bindings` 所使用的具名 Agent 設定檔。
- 每個項目可設定 `provider` + `model`，或在 `model.primary` 中指定完整的 `provider/model` 參照。

範例：

```json
{
  "agents": {
    "list": [
      {
        "id": "coder",
        "model": { "primary": "ollama/qwen3.5:cloud" },
        "system_prompt": "You're an experienced coder"
      }
    ]
  }
}
```

### 子 Agent 設定檔與路由（實踐模式）

當您希望由一個「編排器（Orchestrator）」Agent 將專門任務委派給不同專家時，請使用此模式：

1. 在 `agents.list` 下定義可重複使用的專家 Agent。
2. 在 `agents.defaults` 下保留通用的預設設定。
3. 使用 `bindings` 將特定聊天/主題路由至專門的專家 Agent。
4. 當維運端需要主動執行單次委派時，使用 `/subagents spawn --agent <agent-id> <task>`。

範例：

```json
{
  "agents": {
    "defaults": {
      "model": { "primary": "openrouter/anthropic/claude-sonnet-4" }
    },
    "list": [
      {
        "id": "orchestrator",
        "model": { "primary": "openrouter/anthropic/claude-sonnet-4" },
        "system_prompt": "Coordinate tasks and delegate to specialists."
      },
      {
        "id": "coder",
        "model": { "primary": "openrouter/qwen/qwen3-coder" },
        "system_prompt": "You are focused on implementation and tests."
      },
      {
        "id": "researcher",
        "model": { "primary": "openrouter/openai/gpt-4.1" },
        "system_prompt": "You are focused on investigation and synthesis."
      }
    ]
  }
}
```

注意事項：

- `agents.list[].id` 是 `/subagents spawn --agent <name>`、`delegate` 工具的 `agent` 引數以及 `bindings[].agent_id` 所引用的數值。
- 建議使用簡短穩定的 ID（如 `coder`、`researcher`），保持對話指令簡潔。
- 專家提示詞應保持精確聚焦；範圍過於廣泛的提示詞容易重疊並降低路由判斷的清晰度。

#### `agents.list[].workspace_path`

當具名 Agent 應在自己的工作區而非全域工作區運作時，請使用 `workspace_path`。

範例：

```json
{
  "agents": {
    "list": [
      {
        "id": "coder",
        "model": { "primary": "ollama/qwen2.5-coder:14b" },
        "system_prompt": "Focus on implementation and tests.",
        "workspace_path": "agents/coder"
      }
    ]
  }
}
```

行為特性：

- 相對路徑是相對於包含 `config.json` 的目錄解析。
- 絕對路徑直接按原樣使用。
- 設定檔中同時接受 `/` 與 `\`；執行階段會自動針對當前作業系統正規化分隔符號。
- `workspace_path` 不會停用 `system_prompt`。若兩者皆有設定，NullClaw 會保留具名設定檔的提示詞，並同時從該獨立工作區載入引導上下文。
- 首次使用時，若工作區資料夾不存在，NullClaw 會自動建立基礎架構，包含：
  - `AGENTS.md`
  - `SOUL.md`
  - `IDENTITY.md`
  - `MEMORY.md`

隔離模型：

- 該 Agent 的檔案操作、Markdown 記憶體檔案以及工作區範圍的上下文皆限定在該專屬工作區內。
- 當設定了 `workspace_path` 時，該 Agent 還會獲得形式為 `agent:<agent-id>` 的持久化記憶體命名空間。
- 該命名空間適用於：
  - `nullclaw agent --agent <id>`
  - `/subagents spawn --agent <id> ...`
  - 透過 `bindings` 解析路由至該具名 Agent 的連線階段

實際效果：

- 兩個具名 Agent 可以共享同一個 Provider/Model 系列，但保持各自獨立的持久筆記與工作區目錄。
- `workspace_path` 本身不會自動路由對話。路由依然來自 `bindings`、`/bind` 或明確傳入的 `--agent` / `/subagents spawn --agent`。

### `messages.inbound` 傳入訊息處理

- `debounce_ms` 用於延遲處理連續密集的純文字傳入訊息，將多個簡短片段合併為單一回合。
- 預設值：`3000`（毫秒）。
- 適用於守護行程路由的傳入文字以及 Agent CLI REPL。
- 設為 `0` 可停用防抖處理。
- 斜線指令（Slash commands）與帶有多媒體附件的傳入訊息會繞過防抖機制。
- Telegram 保留其專屬的分割訊息合併路徑；此設定將作為該路徑的基礎防抖時間視窗。

範例：

```json
{
  "messages": {
    "inbound": {
      "debounce_ms": 1500
    }
  }
}
```

### `reliability` 可靠性與重試

- 設定 LLM 提供商的全域重試與故障轉移（Failover）行為。
- `provider_retries`：LLM 請求失敗時的重試次數（預設：2）。
- `provider_backoff_ms`：重試之間的初始指數退避延遲（毫秒，預設：500）。
- `fallback_providers`：當未限定 Provider 的模型需要跨 Provider 尋找時，依序嘗試的 Provider 名稱清單。
- `model_fallbacks`：特定模型至有序備用模型清單的映射。每個備用模型可以是純模型名稱，也可以是明確的 `provider/model` 參照。

範例：

```json
{
  "reliability": {
    "provider_retries": 2,
    "provider_backoff_ms": 500,
    "fallback_providers": ["groq", "openai"],
    "model_fallbacks": [
      {
        "model": "anthropic/claude-sonnet-4",
        "fallbacks": ["openai/gpt-4o", "groq/llama-3.3-70b"]
      }
    ]
  }
}
```

注意事項：

- 純模型名稱的故障轉移順序：主要 Provider 優先，其次依序為各個列出的 `fallback_provider`。
- 限定 Provider 的備用參照（如 `openai/gpt-4o`）會直接路由至該 Provider，跳過通用的 Provider 扇出。
- `api_keys`：（選填）額外的 API 金鑰清單，用於在遇到 429 速率限制錯誤時進行輪替。

### `identity` 身分識別 (AIEOS v1.1)

當您希望執行階段身分由 AIEOS 規範文件驅動時，請使用此區塊。
設定後，NullClaw 會將解析出的 AIEOS 內容與工作區身分檔案（如 `AGENTS.md` 與 `IDENTITY.md`）一同注入系統提示詞中：

```json
{
  "identity": {
    "format": "aieos",
    "aieos_path": "./identity/aieos.identity.json"
  }
}
```

您也可以將相同文件直接內嵌在設定檔中：

```json
{
  "identity": {
    "format": "aieos",
    "aieos_inline": "{\"identity\":{\"names\":{\"first\":\"nullclaw-assistant\"},\"bio\":\"General-purpose autonomous assistant\"},\"linguistics\":{\"style\":\"concise\"},\"motivations\":{\"core_drive\":\"Help the operator finish tasks safely\"}}"
  }
}
```

AIEOS v1.1 最小範例檔案（`identity/aieos.identity.json`）：

```json
{
  "identity": {
    "names": {
      "first": "nullclaw-assistant"
    },
    "bio": "General-purpose autonomous assistant"
  },
  "linguistics": {
    "style": "concise"
  },
  "motivations": {
    "core_drive": "Help the operator finish tasks safely"
  }
}
```

注意事項：

- AIEOS 負載使用頂層區塊，例如 `identity`、`psychology`、`linguistics`、`motivations` 與 `capabilities`。
- 為了便於維護與版本控制可讀性，優先使用 `aieos_path`。
- 僅在需要完全自包含的單一設定檔時才使用 `aieos_inline`。
- 保持 `identity.format` 與負載來源相符（`aieos`）。
- 相對路徑的 `aieos_path` 會優先相對於作用中的工作區解析，其次相對於當前工作目錄。

### `channels` 頻道設定

- 頻道設定位於 `channels.<name>` 之下。
- 支援多帳號的頻道通常使用 `accounts` 包裝器。

外部頻道外掛範例：

```json
{
  "channels": {
    "external": {
      "accounts": {
        "wa-web": {
          "runtime_name": "whatsapp_web",
          "transport": {
            "command": "nullclaw-plugin-whatsapp-web",
            "args": ["--stdio"],
            "timeout_ms": 10000,
            "env": {
              "PLUGIN_TOKEN": "secret"
            }
          },
          "config": {
            "bridge_url": "http://127.0.0.1:3301",
            "allow_from": ["*"]
          }
        }
      }
    }
  }
}
```

外部頻道注意事項：

完整協定、生命週期、元資料慣例與外掛作者契約請參閱 [外部頻道外掛](./external-channels.md)。

- `runtime_name` 是 NullClaw 執行階段頻道 ID，用於路由、綁定、連線階段鍵值與外發派送。切勿重複使用內建頻道名稱或已被其他頻道佔用的名稱。
- `transport.command` 與選填的 `transport.args` 透過 stdio 逐行 JSON-RPC 啟動外掛子行程。
- `transport.timeout_ms` 限制宿主至外掛的 RPC 等待時間；NullClaw 內部對控制平面等待進行上限保護，防止單一損壞外掛卡死監督管理。
- `transport.env` 僅傳遞給外掛行程。
- `config` 必須為 JSON 物件；會作為 `params.config` 轉發至外掛的 `start` 請求中。
- 外掛必須回應 `get_manifest`，並處理 `start`/`send`/`stop`；建議實作 `health`，讓監督機制能偵測已斷線的 Sidecar 而非僅監控行程存活。
- `get_manifest.result` 必須包含 `protocol_version: 2`；`capabilities.health`、`capabilities.streaming`、`capabilities.send_rich`、`capabilities.typing`、`capabilities.edit`、`capabilities.delete`、`capabilities.reactions` 與 `capabilities.read_receipts` 為選填的能力位元。
- `health.result` 必須回報明確的布林值（`healthy`）或明確的健全信號（`ok`、`connected`、`logged_in`）；空物件被視為無效。對於 QR Code/裝置配對型頻道，可在背景驗證仍在進行時回報 `connected: false` 或 `logged_in: false`。
- `start.params` 包含巢狀的 `runtime` 物件（帶有 `name`、`account_id` 與宿主擁有的 `state_dir`）。
- `start.result` 必須包含 `started: true`；本機初始化完成後 `start` 應立即返回，切勿阻塞等待 QR 掃描或人工登入。`send`、`send_rich`、`edit_message`、`delete_message` 與 typing/訊息動作 RPC 在外掛實際接受動作時必須回傳 `result.accepted: true`。單純的 JSON-RPC 成功信封是不夠的。
- `send.params` 包含巢狀的 `runtime` 與 `message` 物件；文字負載使用 `message.text`。
- 若外掛同時聲明了 `capabilities.edit=true` 與 `capabilities.delete=true`，`send.result` 亦可包含 `message_id` 或 `message { target?, message_id }`；這讓 NullClaw 能在不支援原生 `.chunk` 串流的頻道上維持草稿更新追蹤。
- 若 `capabilities.streaming=true`，NullClaw 可在模型串流期間發送 `.chunk` 分階段 `send` 事件。若未設定或為 `false`，NullClaw 僅會發送最終完整回應。
- 若 `capabilities.send_rich=true`，宿主可呼叫帶有巢狀 `runtime` 與 `message { target, text, attachments, choices }` 的 `send_rich`。
- 若 `capabilities.typing=true`，宿主可呼叫帶有巢狀 `runtime` 與 `recipient` 的 `start_typing` / `stop_typing`。
- 若 `capabilities.edit=true` / `capabilities.delete=true`，宿主可呼叫 `edit_message` / `delete_message`。
- 若 `capabilities.reactions=true` 或 `capabilities.read_receipts=true`，宿主可呼叫 `set_reaction` 與 `mark_read`。
- `inbound_message.params.message` 必須包含 `sender_id`、`chat_id` 與 `text`；若存在 `metadata` 必須為 JSON 物件，若存在 `media` 必須為非空字串陣列。
- 若希望路由/綁定能區分未知頻道的私訊與群組對話，請在元資料中帶入 `metadata.peer_kind` 與 `metadata.peer_id`。
- 未知/外部頻道亦可設定 `metadata.is_group`、`metadata.is_dm` 或 `metadata.typing_recipient`；NullClaw 會將該元資料提升納入提示對話脈絡與處理中指示器路由。
- 針對 PR #265 的 WhatsApp Web Sidecar 參考橋接配接器位於 `examples/whatsapp-web/nullclaw-plugin-whatsapp-web`。
- 生產環境配套儲存庫：[nullclaw/nullclaw-channel-baileys](https://github.com/nullclaw/nullclaw-channel-baileys) 與 [nullclaw/nullclaw-channel-whatsmeow-bridge](https://github.com/nullclaw/nullclaw-channel-whatsmeow-bridge)。
- `nullclaw channel start external` 啟動第一個設定的外部帳號；`nullclaw channel start <runtime_name>` 啟動特定執行階段名稱（如 `whatsapp_web`）。

Telegram 範例：

```json
{
  "channels": {
    "telegram": {
      "accounts": {
        "main": {
          "bot_token": "123456:ABCDEF",
          "webhook_secret": "replace-with-random-telegram-webhook-secret",
          "allow_from": ["YOUR_TELEGRAM_USER_ID"]
        }
      }
    }
  }
}
```

WeChat（微信公眾號）範例：

```json
{
  "channels": {
    "wechat": {
      "accounts": {
        "main": {
          "callback_token": "wechat-callback-token",
          "encoding_aes_key": "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG",
          "app_id": "wx1234567890abcdef",
          "app_secret": "wechat-app-secret",
          "allow_from": ["openid_123"]
        }
      }
    }
  }
}
```

WeChat 說明：

- NullClaw 內建支援 WeChat Webhook 頻道；接收公眾號回呼無需額外安裝外部外掛。
- 閘道 Webhook 路徑為 `/wechat`。多帳號時使用 `?account_id=<id>` 查詢參數區分。
- `callback_token` 為簽章驗證必填項。
- `encoding_aes_key` 為選填，但在微信回呼設定為 `encrypt_type=aes` 時為必填。
- `app_id` 與 `app_secret` 為選填，僅在需要透過客服訊息 API 主動發送外發訊息時才需要。
- 空的 `allow_from` 會拒絕傳入訊息；請明確列出受信任的 OpenID，僅在刻意公開的帳號才使用 `"*"`。
- 若編譯時未包含 WeChat 頻道，請使用 `-Dchannels=wechat`（或 `-Dchannels=all`）重新建置。

#### Weixin — 微信 iLink Bot（掃碼登入）

`weixin` 頻道透過 QR Code 授權微信 iLink 機器人。這與上述使用簽章 Webhook 的 `wechat` 公眾號頻道完全獨立。

首先，進行登入並取得 Token：

```bash
nullclaw auth login weixin
```

終端機中會繪製一個 QR Code。使用手機微信掃描並確認授權。該指令會將取得的 `token`，以及在服務回傳非預設主機時的 `base_url` 儲存至您的設定檔中。

登入完成後，編輯由指令更新的 Weixin 帳號設定，明確設定 `allow_from` 清單。在全新設定檔中，其內嵌結構如下所示；若已有現存 `accounts` 物件則保留原結構。登入指令傳入的 `--proxy` 參數亦會儲存於該帳號中，供後續 API 請求重複使用。

```json
{
  "channels": {
    "weixin": {
      "account_id": "default",
      "token": "<bot-token-from-qr-login>",
      "base_url": "https://ilinkai.weixin.qq.com/",
      "proxy": null,
      "allow_from": ["<your-wechat-user-id>"]
    }
  }
}
```

Weixin 頻道欄位說明：

| 欄位 | 預設值 | 說明 |
|---|---|---|
| `account_id` | `"default"` | 路由與連線階段鍵值使用的內部帳號識別碼 |
| `token` | `""` | 來自 `nullclaw auth login weixin` 的機器人 Token（必填） |
| `base_url` | `https://ilinkai.weixin.qq.com/` | 不含 query/fragment 的絕對 HTTPS iLink API 網址（區域重導向後可能變動） |
| `proxy` | `null` | 選填的 `http://`、`https://` 或 `socks5://` Proxy 網址，用於 API 請求 |
| `allow_from` | `[]` | 允許向機器人傳訊的精確微信使用者 ID 清單；請務必明確設定 |

注意事項：

- 在 `allow_from` 明確列出受信任使用者 ID（或明確萬用字元 `"*"`）之前，不會接收任何傳入訊息。
- `nullclaw auth status weixin` 僅報告是否設定了非空 Token，不會向遠端探測連線階段。
- 使用 `nullclaw auth logout weixin` 可移除已設定的 Token。
- 需要 Proxy 時可使用 `nullclaw auth login weixin --proxy http://localhost:7890`；指令會為登入與後續執行階段持久化保存該設定。
- 若編譯時未包含該頻道，請使用 `-Dchannels=weixin`（或 `-Dchannels=all`）重新建置。
- `nullclaw gateway` 會啟動並監督設定的 `weixin` 輪詢迴圈。
- 目前配接器將傳入對話視為私訊並回傳文字；群組路由與多媒體檔案傳輸尚未實作。

#### Telegram 論壇主題討論串（Forum Topics）

- 論壇主題（Topic）的連線階段隔離是自動進行的；`channels.telegram` 下沒有獨立的 `topic_id` 欄位。
- 推薦維運操作流程：
  1. 在 `agents.list` 下設定具名的 Agent 個人設定檔
  2. 開啟目標 Telegram 聊天群組或論壇主題討論串
  3. 執行 `/bind <agent>`
- 若要特定主題使用特定 Agent，請在 `bindings` 中將比對設定為 `match.peer.id = "<chat_id>:thread:<topic_id>"`。
- 若同時需要為該 Telegram 群組的其他部分提供備用 Agent，可為純群組 ID `"<chat_id>"` 新增另一筆綁定。
- `/bind status` 顯示當前生效的路由與可用的 Agent ID。
- `/bind clear` 僅移除當前帳號/聊天/主題的精確綁定，讓路由回退使用更廣泛的比對。
- `/bind` 會為當前 Telegram 帳號與通訊對象寫入精確的 `bindings[]` 項目。
- `/bind status` 能清楚區分當前生效的是精確本地覆寫還是繼承自較廣泛的備用設定。
- 依據路由優先權，主題專屬綁定優先於群組備用綁定；在 `bindings[]` 中的排序先後不影響結果。
- Telegram 選單中 `/bind` 的可見性由 `channels.telegram.accounts.<id>.binding_commands_enabled` 控制。

範例：

```json
{
  "bindings": [
    {
      "agent_id": "coder",
      "match": {
        "channel": "telegram",
        "account_id": "main",
        "peer": { "kind": "group", "id": "-1001234567890:thread:42" }
      }
    },
    {
      "agent_id": "orchestrator",
      "match": {
        "channel": "telegram",
        "account_id": "main",
        "peer": { "kind": "group", "id": "-1001234567890" }
      }
    }
  ]
}
```

在此設定下，主題 `42` 路由至 `coder`，而論壇其餘部分回退使用 `orchestrator`。

> **通訊對象 ID 格式須知**：`bindings` 中的主題對象 ID 必須採用標準的 `:thread:N` 格式（如 `"-1001234567890:thread:42"`）。舊版的 `#topic:N` 格式（如 `"-1001234567890#topic:42"`）在載入時會自動轉換，但已**被廢棄（Deprecated）**——日誌中會出現警告。若在日誌輸出中看到 `#topic:`，複製到設定檔時請轉換為 `:thread:`。`/bind` 指令永遠會自動以正確格式儲存。

具名 Agent 設定檔與綁定是獨立的職責劃分：`agents.list` 定義可重複使用的設定檔，而 `bindings` 決定特定對話/主題使用哪個設定檔。

端到端完整範例：

```json
{
  "agents": {
    "list": [
      {
        "id": "orchestrator",
        "provider": "openrouter",
        "model": "anthropic/claude-sonnet-4"
      },
      {
        "id": "coder",
        "provider": "ollama",
        "model": "qwen2.5-coder:14b",
        "system_prompt": "You are the coding agent for this topic."
      }
    ]
  },
  "channels": {
    "telegram": {
      "accounts": {
        "main": {
          "bot_token": "123456:ABCDEF",
          "webhook_secret": "replace-with-random-telegram-webhook-secret",
          "allow_from": ["YOUR_TELEGRAM_USER_ID"],
          "draft_previews": false,
          "binding_commands_enabled": true,
          "topic_commands_enabled": true,
          "topic_map_command_enabled": true,
          "commands_menu_mode": "scoped"
        }
      }
    }
  },
  "bindings": [
    {
      "agent_id": "orchestrator",
      "match": {
        "channel": "telegram",
        "account_id": "main",
        "peer": { "kind": "group", "id": "-1001234567890" }
      }
    }
  ]
}
```

維運流程：

- 在目標論壇主題中發送 `/bind coder`。
- `nullclaw` 會為該主題與 Telegram 帳號在 `~/.nullclaw/config.json` 中寫入新的精確 `bindings[]` 項目。
- 該主題中的下一則訊息將直接套用新路由的 Agent 設定檔。
- `nullclaw` 行程必須擁有對 `~/.nullclaw/config.json` 的寫入權限，`/bind` 才能成功儲存變更。

關於 `draft_previews`：

- `draft_previews=false` 是預設且建議的設定。
- 停用時，在產生回覆期間 Telegram 仍會顯示輸入狀態指示，但不會使用短暫易變的 `sendMessageDraft` 預覽。
- 僅在明確需要即時部分預覽且能接受 Telegram 可能在最終訊息送達前隱藏並替換草稿的情況下，才設定 `draft_previews=true`。

關於 `account_id`：

- `account_id` 用於識別已設定的 Telegram 帳號項目，而不是主題也不是 Agent。
- 在標準的 `channels.telegram.accounts` 結構中，物件的鍵名即為帳號 ID。例如 `accounts.main` 代表 `account_id = "main"`。
- 在 `bindings` 中，`match.account_id` 將綁定限制在特定 Telegram 帳號。
- 若省略 `match.account_id`，該綁定可比對該頻道下的任何 Telegram 帳號。
- 只有在同一個 NullClaw 執行個體執行多個 Telegram 機器人帳號/Token 時，不同的帳號 ID 才有實質區別。

### Web UI / 瀏覽器轉發

使用 `channels.web` 透過 WebSocket（預設 `/ws`）處理瀏覽器 UI 或擴充功能流量。

範例：

```json
{
  "channels": {
    "web": {
      "accounts": {
        "default": {
          "transport": "local",
          "listen": "127.0.0.1",
          "port": 32123,
          "path": "/ws",
          "auth_token": "replace-with-long-random-token",
          "message_auth_mode": "pairing",
          "allowed_origins": ["http://localhost:5173"]
        }
      }
    }
  }
}
```

實踐原則：

- 本機配對體驗請保持 `listen = "127.0.0.1"`。
- 在本地傳輸模式中，僅在本地迴路上允許未經驗證的 WebSocket 升級請求。這讓前端 UI 能先連線，接著發送 `pairing_request`。
- 本機迴路配對不再依賴固定的共用代碼。`pairing_request` 可以省略 `payload.pairing_code`，而仍發送 `123456` 的舊版客戶端依然保持相容。
- 若將 `listen` 改為 `0.0.0.0` 或其他非本地迴路位址，WebSocket 升級時必須直接包含頻道 Token：
  - `ws://host:32123/ws?token=<auth_token>`
  - 或帶有標頭 `Authorization: Bearer <auth_token>`
- 對於非本機迴路綁定，在 Socket 完成驗證之前，不要期望本地 `pairing_request` 能運作。配對優先流程在設計上僅限本機迴路。
- `message_auth_mode = "pairing"` 代表每則 `user_message` 都必須攜帶配對流程回傳的 UI `access_token`。
- `message_auth_mode = "token"` 僅支援本地傳輸，並要求來自設定或環境變數的穩定 Token。在此模式下，UI 在發送每則 `user_message` 時攜帶 `auth_token` 而非配對 JWT。
- `auth_token` 用於強化 WebSocket 升級安全，且在非本地迴路綁定時為強制必填。
- WebSocket 端點請使用 `/ws`。`/pair` 屬於 HTTP 閘道 API，不屬於 Web 頻道的 WebSocket 流程。
- 針對無周邊/區域網路存取，最安全的維運方式依然是在綁定本地迴路的 Web 頻道前方架設 SSH 通道或反向代理。

遠端/無周邊部署範例：

```json
{
  "channels": {
    "web": {
      "accounts": {
        "default": {
          "transport": "local",
          "listen": "0.0.0.0",
          "port": 32123,
          "path": "/ws",
          "auth_token": "replace-with-long-random-token",
          "message_auth_mode": "token",
          "allowed_origins": ["https://chat-ui.example.com"]
        }
      }
    }
  }
}
```

傳送影響：

- 傳入的 Telegram 更新由接收它的帳號處理。
- 路由使用相同的 `account_id`，因此 `match.account_id = "main"` 僅比對透過 `channels.telegram.accounts.main` 接收的訊息。
- 回覆會透過處理該訊息的同一個 Telegram 帳號/執行環境發送出去。
- 若一筆綁定使用 `account_id = "main"`，另一筆使用 `account_id = "sub"`，它們適用於不同的 Telegram 帳號；這本身不會拆分單一 Telegram 帳號的流量。

安全性規則：

- 空的 `allow_from` 在基於允許清單的頻道上會拒絕傳入訊息。若要建立私密機器人，請明確設定使用者 ID / OpenID。
- `allow_from: ["*"]` 允許所有來源；僅在刻意建立公開機器人時使用。
- Telegram Webhook 要求 `channels.telegram.accounts.<id>.webhook_secret` 與 Telegram 的 `X-Telegram-Bot-Api-Secret-Token` 標頭相符。
- Teams 傳入 Webhook 使用 Bot Framework JWT Bearer Token 對照微軟 OpenID 元資料進行身分驗證。`channels.teams.accounts.<id>.webhook_secret` 為選填，設定時作為額外的 `X-Webhook-Secret` 檢查。

### Max

Max 範例：

```json
{
  "channels": {
    "max": {
      "accounts": {
        "main": {
          "bot_token": "MAX_BOT_TOKEN",
          "allow_from": ["YOUR_MAX_USER_ID"],
          "group_allow_from": ["YOUR_MAX_USER_ID"],
          "group_policy": "allowlist",
          "mode": "webhook",
          "webhook_url": "https://bot.example.com/max?account_id=main",
          "webhook_secret": "replace-with-random-secret",
          "require_mention": true,
          "streaming": true,
          "interactive": {
            "enabled": true,
            "ttl_secs": 900,
            "owner_only": true
          }
        }
      }
    }
  }
}
```

Max 說明：

- `channels.max.accounts` 是帳號物件集合；每個鍵名是區分多個 Max 機器人的 `account_id`。
- 生產環境建議使用 `mode = "webhook"`。Max 官方文件指出長輪詢（Long polling）適合開發/測試，而 Webhook 是推薦的生產模式。
- `webhook_url` 必須使用 HTTPS。
- 在多帳號 Webhook 設定中，為每個帳號提供唯一的 `webhook_secret` 或在 Webhook URL 中帶入唯一的 `account_id` 查詢參數（例如 `/max?account_id=main`）。
- `allow_from` 與 `group_allow_from` 接受 Max `user_id` 或使用者名稱。`user_id` 是綁定與路由的穩定首選。
- `require_mention = true` 僅影響群組聊天。私訊與 `bot_started` 深度連結依然正常運作。
- Max 行內按鈕在 NullClaw 中是一次性的：點擊後會清除原始鍵盤，避免殘留過期按鈕。

### Discord

Discord 範例：

```json
{
  "channels": {
    "discord": {
      "accounts": {
        "default": {
          "token": "YOUR_DISCORD_BOT_TOKEN",
          "intents": 37377,
          "allow_from": ["YOUR_DISCORD_USER_ID"]
        }
      }
    }
  }
}
```

請明確設定 `allow_from`。省略或空的清單會拒絕所有傳入訊息；僅在刻意公開機器人時使用 `["*"]`。

若希望機器人處理一般的伺服器頻道訊息，必須在 Discord Developer Portal 中啟用 **MESSAGE CONTENT INTENT**。未啟用時，Discord 會在大多數公會訊息中省略文字內容；私訊以及直接提及（@mention）機器人的訊息仍會包含內容。

Gateway Intents（`intents`）是一個位元遮罩。預設 37377 = GUILDS (1) + GUILD_MESSAGES (512) + MESSAGE_CONTENT (32768) + DIRECT_MESSAGES (4096)。可至 Discord 開發者文件計算自訂 intents。

Discord 設定步驟：
1. 前往 https://discord.com/developers/applications 建立應用程式
2. 在 Bot 區塊 → Add Bot → Reset Token（立即複製保存）
3. Privileged Gateway Intents 區塊 → 啟用 MESSAGE CONTENT INTENT → 儲存
4. OAuth2 區塊 → URL Generator → Scopes 勾選：`bot`
5. Bot Permissions 勾選：Send Messages、Read Message History、Read Messages/View Channels
6. 複製產生的 URL，在瀏覽器中開啟，選取伺服器並授權加入

目前的 Discord 整合不需要額外的 OAuth Scopes 或如 `Administrator` 等過高權限。

多機器人設定使用 `accounts` 包裝器。每個 `account_id` 會建立獨立的 Discord 連線，具備獨立的連線階段狀態與路由：

```json
{
  "channels": {
    "discord": {
      "accounts": {
        "production": {
          "token": "PRODUCTION_BOT_TOKEN",
          "intents": 37377,
          "allow_from": ["ADMIN_USER_ID"]
        },
        "testing": {
          "token": "TESTING_BOT_TOKEN",
          "intents": 37377,
          "allow_from": ["DEV_USER_ID"]
        }
      }
    }
  }
}
```

頻道專屬綁定使用 `peer.kind = "channel"` 搭配 Discord 頻道 ID（開啟開發者模式 → 右鍵點擊頻道 → 複製 ID）：

```json
{
  "bindings": [
    {
      "agent_id": "coder",
      "match": {
        "channel": "discord",
        "account_id": "default",
        "peer": {"kind": "channel", "id": "CHANNEL_ID_HERE"}
      }
    }
  ]
}
```

私訊綁定使用 `peer.kind = "direct"` 搭配使用者 ID：

```json
{
  "bindings": [
    {
      "agent_id": "personal",
      "match": {
        "channel": "discord",
        "account_id": "default",
        "peer": {"kind": "direct", "id": "USER_ID_HERE"}
      }
    }
  ]
}
```

參數說明：
- `token`（必填）- Discord 開發者後台取得的機器人 Token
- `intents`（預設：37377）- Gateway Intents 位元遮罩
- `allow_bots`（預設：false）- 是否允許接收其他機器人的訊息。機器人自身發送的訊息一律會被忽略
- `allow_from`（預設：[]）- 使用者 ID 允許清單。省略或空清單會拒絕傳入訊息；`["*"]` 明確允許所有使用者
- `require_mention`（預設：false）- 在伺服器群組中是否要求必須 @提及機器人 才會回覆
- `guild_id`（選填）- 保留供 Discord 伺服器範圍限定使用；目前執行環境尚未強制檢查

NullClaw 會自動分割超過 2000 個字元的訊息（Discord API 上限）。

驗證方式：
```bash
nullclaw channel start discord
nullclaw channel status
```

`nullclaw channel start discord` 僅啟動第一個設定的 Discord 帳號。若要驗證多帳號，請執行 `nullclaw gateway` 並向各個機器人發送測試訊息。

常見問題：
- 機器人僅在私訊或明確提及時回應：請在開發者後台啟用 MESSAGE CONTENT INTENT，必要時重新邀請機器人加入伺服器
- "Privileged Intents" 錯誤：在 Discord Developer Portal 中啟用 MESSAGE CONTENT INTENT；已驗證的應用程式可能需要 Discord 官方審查
- 機器人離線：檢查 `nullclaw service status`，確認 Token 未被重設
- 伺服器群組中沒有回應：檢查 `require_mention` 設定，確認機器人具備 Read Messages 讀取權限

### `memory` 記憶體後端

- `backend`：建議起步使用 `sqlite`。可選引擎：`sqlite`、`markdown`、`clickhouse`、`postgres`、`redis`、`lancedb`、`lucid`、`memory`（LRU 快取）、`api`、`none`。
- `auto_save`：自動持久化保存對話記憶。
- 混合檢索與嵌入向量設定請參閱專案根目錄的 `config.example.json`。

**備註**：`markdown_only` 記憶體設定檔會自動啟用帶有時間衰減（半衰期 30 天）的混合檢索機制，以取得最佳相關性評分。這確保了即使使用純 Markdown 檔案也能具備時間感知能力。

### `gateway` 閘道設定

推薦預設值：

- `host = "127.0.0.1"`
- `require_pairing = true`

避免直接對外公開暴露。需要外部存取時請搭配網路通道（Tunnel）。
在非本地迴路綁定時，通用的閘道端點（如 `/webhook`、`/a2a` 與 `/media/transcribe`）即使在停用互動式配對的情況下，依然需要完整的閘道 Bearer Token；因此請維持 `require_pairing = true` 或預先設定 `paired_tokens`。`/cron/*` 端點亦接受下方說明的獨立 cron 範圍憑證。
在非本地迴路綁定時，`/pair` 端點僅接受本地迴路呼叫；在對外暴露閘道前，請先於本地完成配對或預先設定 `paired_tokens`。

當需要 cron 身分驗證時，閘道在啟動時會產生一個僅限存取 `/cron/*` 的 Bearer Token。它僅保留 Token 雜湊值，並將加密憑證以權限 `0600` 寫入設定目錄中的 `paired_token` 檔案，讓 schedule/cron 工具能在 `require_pairing = true` 或閘道公開綁定時進行驗證（包含已預先設定配對 Token 的環境）。該憑證在每次閘道重啟時都會輪替，並非互動式的 `/pair` Token。如同任何 Bearer 憑證，它並未綁定客戶端 IP；請保護設定目錄避免外洩。設定了 `require_pairing = false` 的匿名本地迴路閘道不會建立此憑證。

| 欄位 | 預設值 | 說明 |
|---|---|---|
| `host` | `"127.0.0.1"` | 監聽位址 |
| `port` | `3000` | 監聽連接埠 |
| `require_pairing` | `true` | 所有 API 請求是否要求 Bearer Token 驗證 |
| `allow_public_bind` | `false` | 是否允許綁定至非本地迴路位址 |
| `pair_rate_limit_per_minute` | `10` | 每個 IP 每分鐘最多 `/pair` 請求次數 |
| `webhook_rate_limit_per_minute` | `60` | 每分鐘類似 Webhook 的已驗證請求上限。若是即時 `/media/transcribe` 音訊分塊，請調高此數值。 |
| `idempotency_ttl_secs` | `300` | 冪等性（Idempotent）請求結果快取時長（秒） |
| `max_body_size_bytes` | `65536` | HTTP 請求主體最大大小（位元組，預設 64 KB）。接收圖片、音訊或檔案負載時請調高（例如 `67108864` 代表 64 MiB）。 |
| `request_timeout_secs` | `30` | 傳入 HTTP 請求的 Socket 讀取逾時（秒）。在慢速網路接收大負載時請調高。 |

### `tunnel` 網路通道

將閘道暴露至公開網際網路的通道提供商。在無公網 IP 的環境下執行基於 Webhook 的頻道時為必填。

**提供商清單：**

| 提供商 | 說明 |
|---|---|
| `none` | 不使用通道（預設） |
| `cloudflare` | Cloudflare Tunnel |
| `ngrok` | ngrok 通道 |
| `tailscale` | Tailscale Funnel |
| `custom` | 自訂通道指令 |

**範例：ngrok**

```json
{
  "tunnel": {
    "provider": "ngrok",
    "ngrok": {
      "auth_token": "YOUR_NGROK_AUTH_TOKEN",
      "domain": "your-domain.ngrok-free.app"
    }
  }
}
```

**範例：Cloudflare**

```json
{
  "tunnel": {
    "provider": "cloudflare",
    "cloudflare": {
      "token": "YOUR_CLOUDFLARE_TUNNEL_TOKEN"
    }
  }
}
```

**範例：Tailscale**

```json
{
  "tunnel": {
    "provider": "tailscale",
    "tailscale": {
      "funnel": true,
      "hostname": "nullclaw.ts.net",
      "auth_key": "tskey-auth-..."
    }
  }
}
```

**注意事項：**

- 通道會在閘道之前啟動。
- 公開 URL 會在啟動時印出，並寫入 `daemon_state.json`。
- `tailscale.auth_key` 為選填。用於主機在啟動 `serve`/`funnel` 前自動執行 `tailscale up`。
- 當 `secrets.encrypt = true` 時，通道機密（如 `cloudflare.token`、`ngrok.auth_token` 與 `tailscale.auth_key`）在硬碟中皆會進行靜態加密。

### `autonomy` 自主權限控制

- `level`：建議起步使用 `supervised`（受監督模式）。
- `level = "yolo"`：完全略過指令安全原則檢查；僅限在受信任的本機除錯使用。
- `workspace_only`：保持 `true` 以嚴格限制檔案存取範圍於工作區內。
- `max_actions_per_hour`：初期建議維持保守的上限值。
- `block_high_risk_commands`（預設：`true`）：封鎖具破壞性的指令，如 `rm`、`sudo`、`mkfs`、`dd`、`shutdown`、`ssh`。
- `block_medium_risk_commands`（預設：`true`）：封鎖中度風險指令，包含網路/傳輸指令（如 `curl`、`wget`、`nc`、`scp`、`ftp`、`telnet`）與狀態變更指令（如 `git commit`、`npm install`、`touch`、`mkdir`）。設為 `false` 可允許這些指令，同時依然封鎖高風險指令。
- `require_approval_for_medium_risk`（預設：`true`）：當 `block_medium_risk_commands` 為 `false` 時，在 `supervised` 模式下執行中風險指令前要求使用者明確核准。
- `allowed_commands`：明確允許執行的指令基礎名稱清單。使用 `["*"]` 代表萬用匹配（僅限 full 模式）。不論此清單如何設定，高風險與中風險的執行階段檢查防護門依然生效。

### `security` 安全機制

- `sandbox.backend = "auto"`：自動選取可用的沙盒隔離後端。
- `audit.enabled = true`：強烈建議啟用以確保操作具備可追溯性。

### 進階：網頁搜尋 + 完整 Shell（高風險）

僅限在嚴格受控的環境下使用：

```json
{
  "http_request": {
    "enabled": true,
    "allowed_domains": ["192.168.1.10", "*.internal.example.com"],
    "search_base_url": "https://searx.example.com",
    "search_provider": "auto",
    "search_fallback_providers": ["jina", "duckduckgo"]
  },
  "autonomy": {
    "level": "full",
    "allowed_commands": ["*"],
    "allowed_paths": ["*"],
    "require_approval_for_medium_risk": false,
    "block_medium_risk_commands": false,
    "block_high_risk_commands": false
  }
}
```

注意事項：

- `search_base_url`（供 web_search 工具使用）：必須為 `https://host[/search]` 或本地/私有的 `http://host[:port][/search]` 網址。純 HTTP 僅允許用於 localhost 或私有主機（例如 `http://localhost:8888`、`http://192.168.1.10:8888`）。此 URL 由 `web_search` 工具用於查詢 SearXNG 實例。
- `allowed_commands: ["*"]` 與 `allowed_paths: ["*"]` 會大幅放寬執行與存取權限。
- `http_request.allowed_domains`：允許略過 `http_request` 與 `web_fetch` 工具之 SSRF 防護的網域名稱清單。
  - `[]`（空）：所有網域皆進行 SSRF 檢查（預設，最安全）。
  - `["example.com"]`：僅指定的網域略過 SSRF 檢查。
  - `["*.example.com"]`：匹配所有子網域（如 `api.example.com`、`www.example.com`）。
  - `["192.168.1.10"]`：亦可加入特定 IP 位址（僅限完全相符，不支援 CIDR 區段）。
  - `["*"]`：**極度危險** — 所有網域皆略過 SSRF 檢查與 DNS 固定（Pinning）。僅在您完全掌控 DNS 且需要允許存取任意 IP 的受信任網路環境中使用。這實質上完全停用了 SSRF 防護。
  - **範例**：若您的 SearXNG 服務執行於 `192.168.1.10`，請新增 `"192.168.1.10"` 以便透過 `http_request` 工具存取。
  - **安全性權衡**：允許清單中的網域會略過 DNS Pinning，允許存取私有 IP。這是以犧牲 DNS 重綁定（Rebinding）防護來換取運作彈性。
  - **僅限 HTTPS 原則**：`http_request` 與 `web_fetch` 工具強制要求 `https://` 網址。出於安全考量會直接拒絕純 HTTP。注意：這不影響 `web_search` 工具在本地主機上允許 HTTP 的 `search_base_url`。
  - **檢查順序**：允許清單會在 DNS 解析之前進行檢查，以防止透過 DNS 進行資料外洩攻擊。

## 設定修改後的驗證步驟

每次修改設定後：

```bash
nullclaw doctor
nullclaw status
nullclaw channel status
```

若修改了閘道或頻道設定，一併執行：

```bash
nullclaw gateway
```

## 下一步

- 每次編輯後執行 `nullclaw doctor` 與 `nullclaw status` 確認設定檔仍能正常解析載入
- 參閱 [使用與維運](./usage.md) 了解維運檢查、背景服務模式與疑難排解流程
- 在開啟更廣泛的自主權限、公開綁定或萬用允許清單前，請務必先檢閱 [安全機制](./security.md)

## 相關頁面

- [安裝指南](./installation.md)
- [使用與維運](./usage.md)
- [安全機制](./security.md)
- [Gateway API](./gateway-api.md)
