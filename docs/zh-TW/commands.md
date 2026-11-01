# 指令參考

本頁面依工作任務將 NullClaw CLI 指令分類整理，方便您快速找到合適的指令，無需通篇翻閱完整的說明輸出。

`nullclaw help` 提供最上層的指令摘要；本頁面與其保持一致，並進一步展開詳細子指令與注意事項。

## 頁面導覽

**本頁適合誰**

- 已經安裝 NullClaw 並需要尋找合適 CLI 進入點的使用者
- 查看執行環境、服務、頻道或診斷指令的維運人員
- 驗證指令名稱、旗標與任務分組的貢獻者

**閱讀完後下一步**

- 若需要了解指令所操作的具體設定項目，請參閱 [設定指南](./configuration.md)
- 若需要了解完整工作流程而非僅是指令清單，請參閱 [使用與維運](./usage.md)
- 若您正在修改 CLI 行為或說明文件，請參閱 [開發指南](./development.md)

**如果您是從以下位置跳轉過來**

- [首頁](./README.md)：本頁是快速尋找具體指令的最快途徑
- [安裝指南](./installation.md)：安裝完成後，使用本頁驗證安裝並學習日常指令
- `nullclaw help`：當內建說明過於簡短時，使用本頁獲取更完整的資訊

## 常用起步指令

- 顯示說明：`nullclaw help`
- 顯示版本：`nullclaw version` 或 `nullclaw --version`
- 首次引導設定：`nullclaw onboard --interactive`
- 快速自我檢測：`nullclaw agent -m "hello"`
- 常駐服務模式：`nullclaw gateway`

## 設定與互動

| 指令 | 用途 |
|---|---|
| `nullclaw help` | 顯示最上層說明 |
| `nullclaw version` / `nullclaw --version` | 顯示 CLI 版本 |
| `nullclaw onboard --interactive` | 執行互動式引導設定精靈 |
| `nullclaw onboard --api-key sk-... --provider openrouter` | 快速設定 Provider 與 API 金鑰 |
| `nullclaw onboard --api-key ... --provider ... --model ... --memory ...` | 單一指令同時設定 Provider、Model 與 Memory 後端 |
| `nullclaw onboard --channels-only` | 僅重新設定頻道與允許清單（Allowlist） |
| `nullclaw agent -m "..."` | 執行單次提示詞（Prompt） |
| `nullclaw agent --workspace /path/to/workspace -m "..."` | 指定此行程的工作區目錄並執行單次提示詞 |
| `nullclaw agent --skill news-digest -m "..."` | 啟用指定技能（Skill）並執行單次提示詞 |
| `nullclaw agent` | 啟動互動式對話模式 |
| `nullclaw acp` | 啟動 Agent Client Protocol 的 stdio 配接器（適用於相容 ACP 的編輯器） |
| `nullclaw acp --provider openai --model gpt-5.2` | 為編輯器啟動的連線階段固定特定的 Provider/Model |

### 互動式模型路由

- 在 `nullclaw agent` 互動環境中，`/model` 會顯示當前模型以及所設定的路由/備用（Fallback）狀態。
- `/config reload` 可熱重載 `config.json` 中支援的設定鍵（包含 Agent 個人設定檔）。
- 當設定了自動路由時，`/model` 還會顯示上一次自動路由的決策與選取原因。
- 若路由的 Provider 暫時受到速率限制（Rate-limited）或額度耗盡，`/model` 會將該路由標記為降級，直到冷卻時間結束。
- `/model` 也會列出所有已設定的自動路由，並附帶 `cost_class` 與 `quota_class` 元資料。
- `/model <provider/model>` 可將當前連線階段釘選至特定模型，並停用自動路由。
- `/model auto` 可清除使用者釘選，還原為設定的預設模型，並重新為該連線階段後續回合啟用 `model_routes`。
- 若未設定 `model_routes`，`/model auto` 仍會清除釘選並返回預設模型。
- 啟動 `nullclaw agent` 時若加上 `--model` 或 `--provider`，同樣會釘選該次執行並略過 `model_routes`。
- 啟動 `nullclaw agent` 時若加上 `--skill <name>`，會在第一則訊息或 REPL 第一回合前啟用該技能。
- `nullclaw acp` 透過 stdio 傳輸以換行符分隔的 JSON-RPC。編輯器在建立 ACP 連線階段時會帶入絕對路徑 `cwd`，NullClaw 會將該 cwd 作為 `agent invoke` 的工作區。

## 執行環境與維運

| 指令 | 用途 |
|---|---|
| `nullclaw gateway` | 以設定的主機與連接埠啟動常駐執行環境 |
| `nullclaw gateway --port 8080` | 從 CLI 覆寫閘道連接埠 |
| `nullclaw gateway --host 0.0.0.0 --port 8080` | 從 CLI 覆寫綁定主機與連接埠 |
| `nullclaw gateway --workspace /path/to/workspace` | 覆寫此閘道行程的工作區目錄 |
| `nullclaw service install` | 安裝系統背景服務 |
| `nullclaw service start` | 啟動背景服務 |
| `nullclaw service stop` | 停止背景服務 |
| `nullclaw service restart` | 重新啟動背景服務 |
| `nullclaw service status` | 顯示服務狀態 |
| `nullclaw service uninstall` | 移除系統背景服務 |
| `nullclaw status [--json]` | 顯示整體系統狀態或輸出機器可讀的執行環境快照 |
| `nullclaw doctor` | 執行環境與診斷檢查 |
| `nullclaw update --check` | 檢查是否有可用更新（不安裝） |
| `nullclaw update --yes` | 安裝更新且不進行確認提示 |
| `nullclaw auth login openai-codex` | 透過 OAuth 裝置授權流程登入 `openai-codex` |
| `nullclaw auth login openai-codex --import-codex` | 從 `~/.codex/auth.json` 匯入授權資訊 |
| `nullclaw auth status openai-codex` | 顯示身分驗證狀態 |
| `nullclaw auth logout openai-codex` | 移除已儲存的憑證 |

注意事項：

- `auth` 目前僅支援 `openai-codex`。
- `gateway --host/--port` 僅會覆寫網路綁定設定；其餘閘道安全原則依然取決於設定檔。
- `agent --workspace` 與 `gateway --workspace` 會覆寫當前行程解析後的工作區路徑，效果等同於設定 `NULLCLAW_WORKSPACE` 環境變數。

## 頻道、排程與擴充

### `channel` 頻道管理

| 指令 | 用途 |
|---|---|
| `nullclaw channel list [--json]` | 列出已知與已設定的頻道 |
| `nullclaw channel start` | 啟動預設可用的頻道 |
| `nullclaw channel start telegram` | 啟動特定頻道 |
| `nullclaw channel status` | 顯示頻道健全狀態 |
| `nullclaw channel info <type> [--json]` | 顯示單一頻道類型所設定的帳號資訊 |
| `nullclaw channel add <type>` | 輸出將頻道新增至設定檔的指引說明 |
| `nullclaw channel remove <name>` | 輸出從設定檔中移除頻道的指引說明 |

### `cron` 排程任務

| 指令 | 用途 |
|---|---|
| `nullclaw cron list [--json]` | 列出排程任務 |
| `nullclaw cron status [--json]` | 顯示排程器層級狀態與任務計數器 |
| `nullclaw cron add "0 * * * *" "command"` | 新增定期執行的 Shell 任務 |
| `nullclaw cron add-agent "0 * * * *" "prompt" [--model <model>] [--session-target <isolated\|main>] [--announce] [--channel <name>] [--account <id>] [--to <id>]` | 新增定期執行的 Agent 任務 |
| `nullclaw cron once 10m "command"` | 新增單次延遲執行的 Shell 任務 |
| `nullclaw cron once-agent 10m "prompt" [--model <model>] [--session-target <isolated\|main>] [--announce] [--channel <name>] [--account <id>] [--to <id>]` | 新增單次延遲執行的 Agent 任務 |
| `nullclaw cron run <id>` | 立即執行指定任務 |
| `nullclaw cron pause <id>` / `resume <id>` | 暫停或繼續指定任務 |
| `nullclaw cron remove <id>` | 刪除指定任務 |
| `nullclaw cron runs <id>` | 顯示最近的執行紀錄 |
| `nullclaw cron update <id> --expression ... --command ... --prompt ... --model ... --enable/--disable` | 更新現有任務設定 |

### `skills` 技能管理

| 指令 | 用途 |
|---|---|
| `nullclaw skills list` | 列出已安裝的技能 |
| `nullclaw skills install <source>` | 從 Git 網址、本地路徑或 HTTPS well-known 技能端點安裝 |
| `nullclaw skills install --name <query>` | 搜尋技能登錄庫並安裝最相符的技能 |
| `nullclaw skills remove <name>` | 移除技能 |
| `nullclaw skills info <name>` | 顯示技能元資料 |

### `history` 對話紀錄

| 指令 | 用途 |
|---|---|
| `nullclaw history list [--limit N] [--offset N] [--json]` | 列出對話連線階段清單 |
| `nullclaw history show <session_id> [--limit N] [--offset N] [--json]` | 顯示指定連線階段的訊息紀錄 |

## 資料、模型與工作區

### `memory` 記憶體管理

| 指令 | 用途 |
|---|---|
| `nullclaw memory stats` | 顯示已解析的記憶體設定與統計數據 |
| `nullclaw memory count` | 顯示記憶體項目總數 |
| `nullclaw memory reindex` | 重建向量索引 |
| `nullclaw memory search "query" --limit 10` | 對記憶體進行檢索搜尋 |
| `nullclaw memory get <key>` | 顯示單一記憶體項目 |
| `nullclaw memory list --category task --limit 20` | 按分類列出記憶體項目 |
| `nullclaw memory export-jsonl --limit 1000` | 從記憶體匯出經個資遮蔽（PII-redacted）的標準化 JSONL 資料集 |
| `nullclaw memory hygiene-report --json` | 針對記憶體執行完全重複/正規化重複檢查報告（不修改資料） |
| `nullclaw memory drain-outbox` | 清空持久化向量寄件匣（outbox）佇列 |
| `nullclaw memory forget <key>` | 刪除單一記憶體項目 |

`memory export-jsonl` 每行輸出一筆 JSON 物件，具備穩定的 `schema_version`、`key`、`category`、`timestamp`、`session_id` 與 `content` 欄位結構。除非傳入 `--include-internal`，否則會排除引導/自動儲存內部資料。為了利於資料科學 Notebook、模型評估與外部審查，內容預設已遮蔽敏感個資（PII）；僅在受信任的本機原始匯出時才使用 `--include-pii`。

`memory hygiene-report` 為非破壞性指令。它會掃描選定的記憶體範圍，報告完全重複項目，以及大小寫與空白差異造成的正規化重複項目，不會刪除或覆寫任何資料。

### `workspace`、`capabilities`、`models`、`migrate`

| 指令 | 用途 |
|---|---|
| `nullclaw workspace edit AGENTS.md` | 在 `$EDITOR` 編輯器中開啟引導 Markdown 檔案 |
| `nullclaw workspace reset-md --dry-run` | 預覽工作區 Markdown 檔案重設結果 |
| `nullclaw workspace reset-md --include-bootstrap --clear-memory-md` | 重設內建 Markdown 檔案，並可選擇清除額外檔案 |
| `nullclaw workspace audit` | 掃描工作區檔案是否存在潛在機密外洩（Token 前綴、PEM 區塊、URL 中的認證資訊、高熵字串） |
| `nullclaw workspace audit --staged \| --commit <sha> \| --range a..b` | 針對暫存區變更、歷史 Commit 或 Git 修訂版本範圍執行審計，而非整個工作區目錄 |
| `nullclaw workspace audit --json [--only-secrets] [--fail-on <level>]` | 輸出機器可讀格式供 CI 整合；當發現符合門檻時以非零狀態碼退出 |
| `nullclaw workspace audit --llm-triage external` | 透過 `workspace_audit.llm_triage` 或已設定的主要 LLM Provider 進行發現再分類，使用隱私保護信封架構（原始機密絕不離開本機） |
| `nullclaw workspace audit --llm-provider ollama --llm-model qwen2.5-coder:7b --llm-max-calls 20` | 為單次執行覆寫審計篩檢所用的 Provider、Model 與外部呼叫預算 |
| `nullclaw workspace audit --llm-triage dry-run` | 僅列印將發送的信封內容，不實際呼叫 LLM |
| `nullclaw capabilities` | 顯示文字格式的功能清單摘要 |
| `nullclaw capabilities --json` | 顯示 JSON 格式的功能資訊清單（Manifest） |
| `nullclaw config show [--json]` | 印出磁碟上的完整設定檔 |
| `nullclaw config get <path> [--json]` | 從磁碟讀取以點號分隔的單一設定值 |
| `nullclaw models list` | 列出各 Provider 與預設 Model |
| `nullclaw models info <model>` | 顯示模型詳細資訊 |
| `nullclaw models summary [--json]` | 印出 Provider 與不洩漏金鑰的管理者摘要（供整合使用） |
| `nullclaw models benchmark` | 執行模型延遲效能測試 |
| `nullclaw models refresh` | 重新整理模型型錄 |
| `nullclaw migrate openclaw --dry-run` | 預覽從 OpenClaw 移轉的結果 |
| `nullclaw migrate openclaw --source /path/to/workspace` | 從指定來源工作區進行移轉 |

注意事項：

- `workspace edit` 僅適用於以檔案為基礎的後端（例如 `markdown` 與 `hybrid`）。
- 若引導資料儲存於資料庫後端，CLI 會提示改用 Agent 的 `memory_store` 工具。
- `--json` 唯讀指令主要用於自動化串接以及 NullHub 的受控執行個體管理者 API 邊界。

## 硬體與自動化進入點

### `hardware` 硬體控制

| 指令 | 用途 |
|---|---|
| `nullclaw hardware scan` | 掃描已連接的硬體裝置 |
| `nullclaw hardware flash <firmware_file> [--target <board>]` | 將韌體寫入裝置（目前為佔位指令） |
| `nullclaw hardware monitor` | 監控硬體裝置（目前為佔位指令） |

### 最上層機器面向旗標

這些旗標主要用於自動化、探測或外部整合，而非日常終端機互動：

| 指令 | 用途 |
|---|---|
| `nullclaw --export-manifest` | 匯出執行階段資訊資訊清單（Manifest） |
| `nullclaw --list-models --provider <name> [--api-key <key>] [--base-url <url>]` | 印出模型資訊，包含自訂的 OpenAI 相容端點 |
| `nullclaw --probe-provider-health` | 探測 Model Provider 健全狀態 |
| `nullclaw --probe-channel-health` | 探測 Channel 健全狀態 |
| `nullclaw --from-json` | 執行以 JSON 驅動的進入流程 |

## 推薦疑難排解順序

1. `nullclaw doctor`
2. `nullclaw status`
3. `nullclaw channel status`
4. `nullclaw agent -m "self-check"`
5. 若涉及閘道服務，一併執行 `curl http://127.0.0.1:3000/health`

## 下一步

- 前往 [使用與維運](./usage.md) 了解以任務為基礎的執行工作流程
- 若指令依賴 Provider、Gateway 或 Memory 設定，請參閱 [設定指南](./configuration.md)
- 若您計劃修改指令行為或同步更新程式碼與文件，請參閱 [開發指南](./development.md)

## 相關頁面

- [首頁](./README.md)
- [安裝指南](./installation.md)
- [Gateway API](./gateway-api.md)
- [架構設計](./architecture.md)
