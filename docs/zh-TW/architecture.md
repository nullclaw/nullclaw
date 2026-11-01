# 架構設計

NullClaw 採用虛擬函式表（vtable）驅動的可擴充架構。大部分功能皆透過實作介面並向工廠函式註冊來進行擴充。

## 頁面導覽

**本頁適合誰**

- 在修改程式碼前，想要了解主要子系統邊界劃分的貢獻者
- 審查變更是否符合 vtable 與工廠擴充模式的審查者
- 評估新的 Model Provider、Channel、Tool、Memory 後端或 Runtime 應置於何處的整合者

**閱讀完後下一步**

- 在進行儲存庫程式碼修改或執行貢獻者驗證流程前，請先閱讀 [開發指南](./development.md)
- 如果您的設計涉及閘道（Gateway）、沙盒（Sandbox）、工具（Tools）或安全暴露邊界，請參閱 [安全機制](./security.md)
- 若需要從貢獻者視角切回整體英文/多語系文件索引，請參閱 [首頁](./README.md)

**如果您是從以下位置跳轉過來**

- [開發指南](./development.md)：本頁提供貢獻者工作流程背後的子系統全貌
- [首頁](./README.md)：當您需要深入了解實作層級的設計時，這是更深入的閱讀路徑
- `AGENTS.md`：透過本頁將儲存庫守則與具體模組佈局及擴充接縫連結起來

## 核心設計

- 各子系統透過使用 `ptr: *anyopaque + vtable` 的介面進行抽象化。
- 執行階段（Runtime）實作透過工廠函式進行選取。
- 替換 Provider / Channel / Tool / Memory 不應需要重寫核心編排（Orchestration）邏輯。

## 子系統與擴充點

| 子系統 | 介面 | 內建實作（部分列出） | 擴充方式 |
|---|---|---|---|
| AI 模型 | `Provider` | OpenRouter、Anthropic、OpenAI、Azure OpenAI、Gemini、Vertex AI、Ollama、Groq、Mistral、xAI、DeepSeek、Together、Fireworks、Perplexity、Cohere、Bedrock、Venice、NEAR AI Cloud、Atlas Cloud、Evolink、Eden AI，以及許多相容 OpenAI 協定的端點 | 新增 Provider 實作並註冊 |
| 頻道 | `Channel` | CLI、Telegram、Signal、Discord、Slack、Matrix、WhatsApp、Nostr、IRC、Lark、Line、DingTalk、Email、OneBot、QQ、MaixCam、Mattermost、iMessage、Web、Teams、Max | 新增 Channel 實作並註冊 |
| 記憶體 | `Memory` | SQLite（混合檢索）、Markdown、ClickHouse、PostgreSQL、Redis、LanceDB、Lucid、LRU、API、None | 新增 Memory 後端 |
| 工具 | `Tool` | shell、file_read、file_write、file_edit、file_edit_hashed、file_read_hashed、file_append、http_request、web_fetch、web_search、delegate、screenshot、browser_open，以及其他 20 多種工具 | 新增 Tool 實作 |
| 可觀測性 | `Observer` | Noop、Log、File、Multi | 新增 Observer 後端 |
| 執行環境 | `RuntimeAdapter` | Native、Docker、WASM | 新增 Runtime 配接器 |
| 安全機制 | `Sandbox` | Landlock、Firejail、Bubblewrap、Docker(auto) | 新增 Sandbox 後端 |
| 網路通道 | `Tunnel` | None、Cloudflare、Tailscale、ngrok、Custom | 新增 Tunnel 提供者 |
| 硬體周邊 | `Peripheral` | Serial、Arduino、RPi GPIO、STM32/Nucleo | 新增硬體驅動程式 |

## 記憶體技術棧

| 層級 | 實作細節 |
|---|---|
| 向量檢索 | 嵌入向量（Embeddings）以 BLOB 格式存於 SQLite 中，支援餘弦相似度搜尋 |
| 關鍵字檢索 | 使用 SQLite FTS5 與 BM25 演算法 |
| 混合合併 | 加權向量 + 關鍵字合併 |
| 嵌入向量 | `EmbeddingProvider` vtable（支援 OpenAI / 自訂 / noop） |
| 資料維護 | 自動封存與清理機制 |
| 快照 | 完整的匯出 / 匯入移轉路徑 |
| 儲存引擎 | SQLite（預設）、Markdown、ClickHouse、PostgreSQL、Redis、LanceDB、Lucid、LRU、API、None |

## 實踐約束原則

1. 優先透過介面實作進行功能擴充，而非侵入性地重構核心邏輯。
2. 保持嚴格的子系統邊界（避免跨子系統的內部強烈耦合）。
3. 針對高風險路徑（`security/runtime/gateway/tools`），必須包含邊界與錯誤路徑驗證測試。

## 下一步

- 閱讀 [開發指南](./development.md) 了解貢獻者工作流程、測試驗證要求與 PR 準備步驟
- 修改本頁所提及的任何高風險子系統前，請先檢閱 [安全機制](./security.md)
- 若需要查看整體說明文件地圖，請返回 [首頁](./README.md)

## 相關頁面

- [首頁](./README.md)
- [開發指南](./development.md)
- [安全機制](./security.md)
- [指令參考](./commands.md)
