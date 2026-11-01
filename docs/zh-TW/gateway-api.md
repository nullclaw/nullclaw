# Gateway API 閘道介面

預設閘道端點：`http://127.0.0.1:3000`

## 頁面導覽

**本頁適合誰**

- 將外部系統串接至本地閘道的維運人員
- 測試配對、Bearer Token 驗證與 Webhook 傳送的整合者
- 審查 HTTP 介面預設開放範圍的審查者

**閱讀完後下一步**

- 在將閘道暴露於本地迴路（Loopback）或通道預設之外前，請先閱讀 [安全機制](./security.md)
- 若需要這些範例背後具體的 `gateway` 與頻道設定鍵，請參閱 [設定指南](./configuration.md)
- 關於閘道行為的執行階段檢查、重啟與疑難排解，請參閱 [使用與維運](./usage.md)

**如果您是從以下位置跳轉過來**

- [使用與維運](./usage.md)：本頁提供閘道健全檢查與 Webhook 檢查背後的端點層級詳細資訊
- [安全機制](./security.md)：當安全審查需要具體的 HTTP 驗證與端點暴露資訊時，請參閱本頁
- [設定指南](./configuration.md)：修改 `gateway` 設定後，返回此處驗證對外 API 的行為

## 端點清單

| 端點 | 方法 | 身分驗證 | 說明 |
|---|---|---|---|
| `/health` | GET | 無 | 健全狀態檢查 |
| `/pair` | POST | `X-Pairing-Code` | 使用一次性配對碼交換 Bearer Token（當閘道公開綁定時僅限本地迴路呼叫） |
| `/webhook` | POST | `Authorization: Bearer <token>` | 發送訊息負載：`{"message":"..."}` |
| `/media/transcribe` | POST | `Authorization: Bearer <token>` | 透過已設定的語音轉文字（STT）Provider 轉譯 Base64 音訊資料 |
| `/cron` | GET | Cron 專屬 Bearer 或閘道通用 Bearer（當要求驗證時） | 列出執行中守護行程（Daemon）的即時排程任務 |
| `/cron/add` | POST | Cron 專屬 Bearer 或閘道通用 Bearer（當要求驗證時） | 新增或排定即時 cron 任務 |
| `/cron/remove` | POST | Cron 專屬 Bearer 或閘道通用 Bearer（當要求驗證時） | 依據 `id` 移除即時 cron 任務 |
| `/cron/pause` | POST | Cron 專屬 Bearer 或閘道通用 Bearer（當要求驗證時） | 依據 `id` 暫停即時 cron 任務 |
| `/cron/resume` | POST | Cron 專屬 Bearer 或閘道通用 Bearer（當要求驗證時） | 依據 `id` 恢復即時 cron 任務 |
| `/cron/update` | POST | Cron 專屬 Bearer 或閘道通用 Bearer（當要求驗證時） | 部分更新即時 cron 任務 |
| `/telegram` | POST | 符合 `channels.telegram.accounts.<id>.webhook_secret` 的 `X-Telegram-Bot-Api-Secret-Token` | Telegram 傳入 Webhook |
| `/whatsapp` | GET | 查詢參數（Query Parameters） | Meta Webhook 驗證 |
| `/whatsapp` | POST | Meta 簽章（Signature） | WhatsApp 傳入 Webhook |
| `/max` | POST | 已設定時要求 `X-Max-Bot-Api-Secret` | Max 傳入 Webhook 傳送 |
| `/api/messages` | POST | `Authorization: Bearer <Bot Framework JWT>` 與選填的 `X-Webhook-Secret` | Teams Bot Framework 傳入 Webhook |
| `/.well-known/agent-card.json` | GET | 無 | A2A Agent Card 探索檔案（公開） |
| `/a2a` | POST | `Authorization: Bearer <token>` | A2A JSON-RPC 2.0 端點 |

## 快速範例

### 1) 健全狀態檢查

```bash
curl http://127.0.0.1:3000/health
```

### 2) 配對並取得 Token

```bash
curl -X POST \
  -H "X-Pairing-Code: PAIRING_CODE" \
  http://127.0.0.1:3000/pair
```

預期回傳：包含 Bearer Token 的回應（具體 JSON 欄位依版本可能有些微差異）。

### 3) 發送 Webhook 訊息

```bash
curl -X POST \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"message":"hello from webhook"}' \
  http://127.0.0.1:3000/webhook
```

### 4) 列出即時 cron 任務

```bash
curl -X GET \
  -H "Authorization: Bearer YOUR_TOKEN" \
  http://127.0.0.1:3000/cron
```

### 5) 新增即時 cron 任務

```bash
curl -X POST \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"expression":"*/15 * * * *","command":"echo hello"}' \
  http://127.0.0.1:3000/cron/add
```

`/cron/add` 亦支援單次延遲負載（例如 `{"delay":"10m","command":"echo later"}`）與 Agent 任務負載（例如 `{"expression":"0 * * * *","prompt":"Summarize alerts","model":"openrouter/anthropic/claude-sonnet-4"}`）。

### 6) Max Webhook 傳送

單一帳號範例：

```bash
curl -X POST \
  -H "Content-Type: application/json" \
  -H "X-Max-Bot-Api-Secret: YOUR_MAX_SECRET" \
  -d '{"update_type":"bot_started","chat_id":100,"timestamp":1710000000000,"user":{"user_id":42,"first_name":"Igor"}}' \
  http://127.0.0.1:3000/max
```

多帳號範例：

```bash
curl -X POST \
  -H "Content-Type: application/json" \
  -H "X-Max-Bot-Api-Secret: YOUR_MAX_SECRET" \
  -d '{"update_type":"message_created","timestamp":1710000000000,"message":{"sender":{"user_id":42,"first_name":"Igor"},"recipient":{"chat_id":100,"chat_type":"dialog"},"body":{"mid":"m1","text":"ping"}}}' \
  "http://127.0.0.1:3000/max?account_id=main"
```

Max Webhook 說明：

- `nullclaw` 在處理 `/max` 時，會優先依據 `account_id` 查詢參數路由到對應的 Max 帳號，其次根據 `X-Max-Bot-Api-Secret`。
- 若設定了 `channels.max.accounts.<id>.webhook_secret`，則此標頭為必填且必須完全相符。
- 在 Max 端設定 Webhook URL 時請一律使用 HTTPS。

Teams Webhook 說明：

- `nullclaw` 在接受活動請求前，會對照微軟的 OpenID 元資料與簽章金鑰驗證 Bot Framework Bearer Token。
- Token 簽發者必須為 `https://api.botframework.com`，受眾（Audience）必須符合設定的 Teams `client_id`，且 Token 的 `serviceUrl` 必須與活動內容相符。
- 透過公開的 Bot Framework 金鑰元資料強制執行 Teams `channelId` 背書檢查。
- 若設定了 `channels.teams.accounts.<id>.webhook_secret`，`X-Webhook-Secret` 亦必須完全相符。

## 媒體語音轉文字

`POST /media/transcribe` 專為本機編排器設計。它要求與 `/webhook` 及 `/a2a` 相同的 Bearer Token 驗證，並使用已設定的 `tools.media.audio` STT 模型。

請求範例：

```json
{
  "audio_base64": "BASE64_AUDIO_BYTES",
  "mime_type": "audio/webm;codecs=opus",
  "source": "mic",
  "language": "en"
}
```

回應範例：

```json
{
  "text": "transcribed speech",
  "source": "mic",
  "language": "en",
  "mime_type": "audio/webm;codecs=opus"
}
```

注意事項：

- `audio_base64` 為必填；`mime_type` 預設為 `audio/ogg`。
- 僅接受 `audio/*` 類型的 MIME Type。
- 若進行即時桌面音訊分塊傳輸，請調高 `gateway.max_body_size_bytes`、`gateway.request_timeout_secs` 與 `gateway.webhook_rate_limit_per_minute`。
- `tools.media.audio.models[0]` 用於選取 STT Provider/Model/端點。若該 Provider 沒有設定金鑰，NullClaw 會在可用時自動降級回退至有金鑰的 OpenAI/Groq/Telnyx Provider。
- 遠端主機的自訂 STT 端點必須使用 HTTPS；純 HTTP 僅允許用於本機/私有端點，且帶有查詢字串或 fragment 的 URL 會被拒絕。

## A2A（Agent-to-Agent 協定）

NullClaw 基於 JSON-RPC 2.0 實作了 [Google A2A 協定 v0.3.0](https://github.com/google/A2A)，可與任何相容 A2A 的代理人或客戶端互相通訊。

### 設定方式

在 `~/.nullclaw/config.json` 中加入：

```json
{
  "a2a": {
    "enabled": true,
    "name": "My Agent",
    "description": "General-purpose AI assistant",
    "url": "https://your-public-url.example.com",
    "version": "0.3.0"
  }
}
```

| 欄位 | 預設值 | 說明 |
|---|---|---|
| `enabled` | `false` | 是否啟用 A2A 端點 |
| `name` | `"NullClaw"` | Agent Card 中的代理人名稱 |
| `description` | `"AI assistant"` | 代理人描述 |
| `url` | `""` | 公開 URL（用於 Agent Card 與 `supportedInterfaces`） |
| `version` | `"1.0.0"` | 代理人版本字串 |
| `multi_modal` | `false` | 在 Agent Card 中宣告多模態能力。當設定的模型支援圖片輸入時設為 `true`。閘道會在啟動時探測模型並自動設定；如有需要亦可手動覆寫。 |

**多模態支援**

當 `multi_modal` 為 `true` 時，Agent Card 會在其 capabilities 物件中包含 `"multi_modal": true`，向 A2A 客戶端宣告本代理人支援圖片附件。傳入的 A2A 訊息除了 `text` 內容外，還可以包含 `inlineData` 部分（Base64 編碼的圖片）；閘道會將其轉換為 `[IMAGE: <mime_type>]` 標記轉發給模型。

若要接收大型圖片負載，請在 `gateway` 設定區塊中提高閘道的 HTTP 主體上限與通訊端讀取逾時時間（參閱 [設定指南](./configuration.md) 的 `gateway` 章節）：

```json
{
  "gateway": {
    "max_body_size_bytes": 67108864,
    "request_timeout_secs": 120
  }
}
```

### Agent Card 探索

```bash
curl http://127.0.0.1:3000/.well-known/agent-card.json
```

回傳包含功能、技能、安全方案與支援介面的 Agent Card。此端點無需身分驗證。

### JSON-RPC 方法

所有方法皆透過 `POST /a2a` 呼叫，並附帶從 `/pair` 取得的 Bearer Token。

| 方法 | 說明 |
|---|---|
| `message/send` | 發送訊息，接收完成後的任務結果 |
| `message/stream` | 發送訊息，透過 SSE 串流接收事件 |
| `tasks/get` | 依 ID 取得任務資訊（支援 `historyLength`） |
| `tasks/cancel` | 取消進行中的任務 |
| `tasks/list` | 列出任務，支援 `state` / `contextId` 選用篩選條件 |
| `tasks/resubscribe` | 為現有任務重新訂閱 SSE 串流 |

### 任務生命週期

```
submitted → working → completed
                    → failed
                    → canceled
                    → input-required
                    → auth-required
                    → rejected
```

終止狀態（Terminal States）：`completed`、`failed`、`canceled`、`rejected`。

### 範例

**發送訊息：**

```bash
curl -X POST \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "message/send",
    "params": {
      "message": {
        "messageId": "msg-1",
        "role": "user",
        "parts": [{"kind": "text", "text": "What is nullclaw?"}]
      }
    }
  }' \
  http://127.0.0.1:3000/a2a
```

**串流回應（SSE）：**

```bash
curl -N -X POST \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "message/stream",
    "params": {
      "message": {
        "messageId": "msg-2",
        "role": "user",
        "parts": [{"kind": "text", "text": "Explain A2A protocol"}]
      }
    }
  }' \
  http://127.0.0.1:3000/a2a
```

**取得任務：**

```bash
curl -X POST \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tasks/get","params":{"id":"task-1"}}' \
  http://127.0.0.1:3000/a2a
```

**取消任務：**

```bash
curl -X POST \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":3,"method":"tasks/cancel","params":{"id":"task-1"}}' \
  http://127.0.0.1:3000/a2a
```

### 多回合對話

在訊息中帶入 `contextId` 可將多個任務歸組為同一個對話。所有具有相同 `contextId` 的訊息將共享連線階段狀態與歷史對話：

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "message/send",
  "params": {
    "message": {
      "messageId": "msg-3",
      "contextId": "my-conversation",
      "role": "user",
      "parts": [{"kind": "text", "text": "Follow-up question"}]
    }
  }
}
```

### 錯誤代碼

| 代碼 | 名稱 | 說明 |
|---|---|---|
| -32700 | JSONParseError | 無效的 JSON 內容 |
| -32600 | InvalidRequestError | 請求驗證錯誤 |
| -32601 | MethodNotFoundError | 未知的方法 |
| -32602 | InvalidParamsError | 缺少參數或參數無效 |
| -32603 | InternalError | 伺服器端錯誤 |
| -32001 | TaskNotFoundError | 找不到指定的任務 ID |
| -32002 | TaskNotCancelableError | 任務已處於終止狀態，無法取消 |
| -32003 | PushNotificationNotSupportedError | 不支援推播通知 |
| -32005 | ContentTypeNotSupportedError | 不相容的內容類型 |
| -32007 | AuthenticatedExtendedCardNotConfiguredError | 擴充卡未設定 |

## 安全指引

1. 維持 `gateway.require_pairing = true`。
2. 讓閘道保持綁定在本地迴路（`127.0.0.1`），並透過網路通道或反向代理對外暴露。
3. 若刻意綁定非本地迴路位址，通用端點（`/webhook`、`/a2a`、`/media/transcribe`）即使在停用互動式配對的情況下，依然需要完整的閘道 Bearer Token；若不使用 `/pair`，請預先設定 `gateway.paired_tokens`。`/cron/*` 端點亦接受其專屬的 cron 範圍 Bearer。
4. 在非本地迴路綁定時，`/pair` 僅接受來自本地迴路的請求。在對外開放連接埠前，請先於本地完成配對或預先設定 `gateway.paired_tokens`。
5. 將 Bearer Token 視為機密憑證；切勿提交或寫入日誌。
6. 對待 Max Webhook 機密應採取相同標準：為每個帳號產生隨機機密，切勿跨機器人重複使用同一金鑰。
7. 當需要 cron 身分驗證時，閘道在啟動時會產生一個僅限存取 `/cron/*` 的 Bearer Token，保留其雜湊值，並將加密後的憑證寫入設定目錄中的 `paired_token` 檔案（權限為 `0600`）。schedule/cron 工具會讀取此檔案以發送控制平面請求。此 Token 會在每次閘道重啟時輪替，且無法授權 webhook、A2A、media 或其他管理路由。它依然是 Bearer 憑證而非綁定 IP 的本地來源證明，因此請保護設定目錄避免外洩。設定了 `require_pairing = false` 的匿名本機迴路閘道則不會建立此檔案。

## 下一步

- 在變更公開暴露、配對或 Token 處理假設前，請先檢閱 [安全機制](./security.md)
- 參閱 [設定指南](./configuration.md) 了解支援本頁範例的各項設定鍵
- 參閱 [使用與維運](./usage.md) 了解閘道啟動、健全檢查與變更後驗證流程

## 相關頁面

- [設定指南](./configuration.md)
- [使用與維運](./usage.md)
- [安全機制](./security.md)
- [首頁](./README.md)
