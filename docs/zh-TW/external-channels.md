# 外部頻道外掛

本頁面介紹 `channels.external` 執行環境，以及無需將特定頻道程式碼合併入核心即可新增訊息通訊頻道的外部外掛協定。

## 頁面導覽

**本頁適合誰**

- 在 `config.json` 中設定外部頻道的維運人員
- 實作新頻道橋接器的外掛作者
- 審查新整合應該納入核心還是作為外掛實作的維護者

**閱讀完後下一步**

- 參閱 [設定指南](./configuration.md) 了解完整的設定檔脈絡
- 參閱 [架構設計](./architecture.md) 了解更全面的執行階段模型
- 在驗證線上部署環境時，請參閱 [使用與維運](./usage.md)

## 為什麼需要外部頻道

`channels.external` 是社群或特定站點專屬頻道的標準擴充途徑。其設計目標為：

- 將特定頻道的 SDK、Sidecar 與橋接邏輯排除在 NullClaw 核心之外
- 避免同行程內的 ABI 與動態外掛載入複雜度
- 允許個別頻道的程式碼以獨立儲存庫與不同程式語言進行開發
- 維持宿主契約（Host contract）精簡、明確且易於監督管理

宿主與外掛之間的邊界定義：

- 傳輸方式：透過 `stdin` / `stdout` 傳輸逐行分隔的 JSON-RPC
- 行程模型：由 NullClaw 啟動的子行程
- 路由介面：僅限通用的 `Channel` 操作
- 頻道專屬行為：完全在外掛內部實作

## 何時使用外部頻道

符合以下情況時，請使用外部頻道外掛：

- 該頻道需要龐大的 SDK 或非 Zig 的第三方程式庫相依性
- 該整合屬於小眾、實驗性質或僅適用於特定維運組織
- 該頻道最適合透過本機 Sidecar 或橋接服務來呈現
- 您希望擺脫 NullClaw 核心版本的發行週期，獨立快速迭代

不適合使用的情況：

- 該功能本質上屬於產品或應用程式層，而非訊息傳遞頻道
- 您需要修改核心的路由、記憶體、安全或 Agent 語意
- 該整合更適合以工具（Tools）或 MCP 呈現，而非訊息傳輸管道

## 設定模型

外部頻道設定位於 `channels.external.accounts.<id>` 之下。

範例：

```json
{
  "channels": {
    "external": {
      "accounts": {
        "wa-web": {
          "runtime_name": "whatsapp_web",
          "transport": {
            "command": "/opt/nullclaw/plugins/nullclaw-plugin-whatsapp-web",
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

欄位說明：

- `runtime_name`
  路由、綁定、連線階段鍵值、守護行程派送與 `nullclaw channel start <runtime_name>` 使用的執行階段頻道名稱。
- `transport.command`
  外掛行程的可執行檔路徑或指令名稱。
- `transport.args`
  選填的引數陣列。
- `transport.env`
  僅傳遞給該外掛行程的選填環境變數。
- `transport.timeout_ms`
  個別帳號等待宿主 RPC 回應的逾時上限（毫秒）。宿主內部對監控敏感的請求仍會套用更短的上限。
- `config`
  傳遞給外掛 `start` RPC 作為 `params.config` 的不透明 JSON 物件。

驗證規則：

- `runtime_name` 必須非空，且僅能包含英文字母、數字、`_`、`-` 或 `.`
- `runtime_name` 在內建與已設定的執行階段頻道中必須全域唯一
- `transport.command` 為必填
- `transport.timeout_ms` 必須介於 `[1, 600000]` 之間
- `config` 必須為 JSON 物件

## 執行階段架構

在執行階段，宿主會建立通用的 `ExternalChannel`，負責：

1. 啟動外掛子行程
2. 擷取並驗證外掛資訊清單（Manifest）
3. 發送 `start` 生命週期指令
4. 將通用的 `Channel` 操作映射為 JSON-RPC 請求
5. 接收 `inbound_message` 通知並將其發布至訊息匯流排
6. 透過有時間上限的探測檢查監督外掛健康狀態

重要特性：

- 一個已設定的帳號對應一個外掛子行程
- 外掛與其他原生頻道執行環境一樣受到完全的監控管理
- 外掛的 stdout 僅專供 JSON-RPC 逐行訊息使用
- 外掛的 stderr 可自由用於除錯診斷日誌

## 傳輸協定約定

傳輸格式為透過標準輸入輸出（stdio）傳輸的換行符分隔 JSON-RPC 2.0。

通訊規則：

- 每個請求、回應或通知都必須是單行文字
- stdout 必須只包含 JSON-RPC 格式內容
- stderr 為自由文字格式，不參與通訊協定
- 請求與回應的配對使用 JSON-RPC `id`
- 下文要求處，`params` 與 `result` 負載必須為 JSON 物件

## 資訊清單（Manifest）

宿主會發出請求：

```json
{"jsonrpc":"2.0","id":1,"method":"get_manifest","params":{}}
```

外掛必須回傳：

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "protocol_version": 2,
    "capabilities": {
      "health": true,
      "streaming": false,
      "send_rich": false,
      "typing": false,
      "edit": false,
      "delete": false,
      "reactions": false,
      "read_receipts": false
    }
  }
}
```

規則：

- `protocol_version` 必須為 `2`
- `capabilities` 為選填
- 未聲明的功能位元一律視為不支援

功能能力意義：

- `health`
  外掛實作了 `health` RPC，能回報頻道層級的健全狀態。
- `streaming`
  外掛接受模型串流輸出的分階段 `.chunk` 外發事件。
- `send_rich`
  外掛實作了 `send_rich`。
- `typing`
  外掛實作了 `start_typing` 與 `stop_typing`。
- `edit`
  外掛實作了 `edit_message`，支援宿主後續更新訊息。
- `delete`
  外掛實作了 `delete_message`，支援宿主進行訊息清理。
- `reactions`
  外掛實作了 `set_reaction`（表情符號回應）。
- `read_receipts`
  外掛實作了 `mark_read`（已讀標記）。

## 生命週期 RPC

### `start`

宿主請求：

```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "start",
  "params": {
    "runtime": {
      "name": "whatsapp_web",
      "account_id": "wa-web",
      "state_dir": "/home/user/.nullclaw/workspace/state/channels/external/whatsapp_web/wa-web"
    },
    "config": {
      "bridge_url": "http://127.0.0.1:3301",
      "allow_from": ["*"]
    }
  }
}
```

必要的成功回應：

```json
{"jsonrpc":"2.0","id":2,"result":{"started":true}}
```

注意事項：

- `runtime.state_dir` 是宿主為外掛帳號所保留的持久化存儲目錄
- 外掛應將 `config` 視為外掛本地專屬的不透明設定
- 未包含 `result.started: true` 的 JSON-RPC 成功回應將被視為失敗拒絕
- 一旦外掛行程完成其內部狀態初始化，`start` 應立即回傳；切勿因等待 QR Code 掃描、裝置配對或人工登入而長時間阻塞 `start`
- 若首次執行的身分驗證仍在進行中，請回傳 `started: true`，並透過 `health` 端點暴露此狀態

### `stop`

宿主請求：

```json
{"jsonrpc":"2.0","id":3,"method":"stop","params":{}}
```

宿主除合法的 JSON-RPC 成功回應外不強制要求特殊負載，但仍建議回傳結果物件。

## 健全狀態 RPC

若聲明了 `capabilities.health=true`，宿主可能會呼叫：

```json
{"jsonrpc":"2.0","id":4,"method":"health","params":{}}
```

接受的回應格式：

```json
{"jsonrpc":"2.0","id":4,"result":{"healthy":true}}
```

或

```json
{"jsonrpc":"2.0","id":4,"result":{"ok":true,"connected":true,"logged_in":true}}
```

規則：

- 若存在 `healthy` 欄位，其值必須為布林值
- 否則，必須至少包含 `ok`、`connected`、`logged_in` 其中之一
- 空的 `{}` 結果為無效
- 若外掛不支援 `health`，請勿聲明該功能位元，切勿回傳虛假的成功

建議的非同步登入驗證行為：

- 當啟動成功但認證仍待處理時，立即回應 `start`，並於 `health` 中回報 `connected: false` 及/或 `logged_in: false`
- 保留 `healthy: false` 僅用於外掛執行環境本身發生故障的情況，而非僅僅是在等待掃描 QR Code
- 登入完成後，`health` 應自動收斂至 `connected: true` 與 `logged_in: true`，而無需宿主重啟外掛

## 外發訊息 RPC

### `send`

宿主請求：

```json
{
  "jsonrpc": "2.0",
  "id": 5,
  "method": "send",
  "params": {
    "runtime": {
      "name": "whatsapp_web",
      "account_id": "wa-web"
    },
    "message": {
      "target": "room-1",
      "text": "hello",
      "stage": "final",
      "media": []
    }
  }
}
```

必要的成功回應：

```json
{"jsonrpc":"2.0","id":5,"result":{"accepted":true}}
```

若外掛同時宣告了 `capabilities.edit=true` 與 `capabilities.delete=true`，`send` 亦可回傳穩定的訊息參考識別碼，以便宿主後續更新或刪除該訊息：

```json
{"jsonrpc":"2.0","id":5,"result":{"accepted":true,"message_id":"msg-42"}}
```

或

```json
{"jsonrpc":"2.0","id":5,"result":{"accepted":true,"message":{"target":"room-1","message_id":"msg-42"}}}
```

規則：

- `message.target` 為外掛自訂的頻道目標識別資料
- 文字欄位名稱一律為 `message.text`；不再支援 `content`
- `message.stage` 為 `"final"` 或 `"chunk"`
- `message.media` 為字串陣列
- 若外掛無法或不接受發送，絕不能偽造成功
- 當使用宿主管理的後續編輯/刪除功能時，`message_id` 必須為非空的穩定平台識別碼
- `result.message.target` 為選填；若省略，宿主將重複使用原始外發目標
- 未聲明 `edit` + `delete` 的外掛可僅回傳 `{"accepted": true}`

宿主目前會區分：

- JSON-RPC 成功：代表請求傳輸完成
- `result.accepted: true`：代表外掛確實接受了該動作

回傳 `{"accepted": false}` 將被視為遭拒絕的動作，而非成功。

### `send_rich`

僅在 `capabilities.send_rich=true` 時呼叫。

宿主請求：

```json
{
  "jsonrpc": "2.0",
  "id": 6,
  "method": "send_rich",
  "params": {
    "runtime": {
      "name": "plugin_chat",
      "account_id": "main"
    },
    "message": {
      "target": "room-1",
      "text": "Choose one",
      "attachments": [
        {
          "kind": "image",
          "target": "/tmp/card.png",
          "caption": "preview"
        }
      ],
      "choices": [
        {
          "id": "yes",
          "label": "Yes",
          "submit_text": "yes"
        }
      ]
    }
  }
}
```

必要的成功回應：

```json
{"jsonrpc":"2.0","id":6,"result":{"accepted":true}}
```

附件 `kind` 類型：

- `image`（圖片）
- `document`（文件）
- `video`（影片）
- `audio`（音訊）
- `voice`（語音）

若不支援 `send_rich`，請勿設定該能力位元。當負載內容足夠簡單時，宿主可降級回退使用純文字 `send`。

### `edit_message`

僅在 `capabilities.edit=true` 時呼叫。

宿主請求：

```json
{
  "jsonrpc": "2.0",
  "id": 7,
  "method": "edit_message",
  "params": {
    "runtime": {
      "name": "plugin_chat",
      "account_id": "main"
    },
    "message": {
      "target": "room-1",
      "message_id": "msg-42",
      "text": "patched",
      "attachments": [],
      "choices": []
    }
  }
}
```

必要的成功回應：

```json
{"jsonrpc":"2.0","id":7,"result":{"accepted":true}}
```

在不支援原生 `.chunk` 串流的頻道上，宿主可在先前 `send` 發送後使用此方法來更新受追蹤的訊息草稿。

### `delete_message`

僅在 `capabilities.delete=true` 時呼叫。

宿主請求：

```json
{
  "jsonrpc": "2.0",
  "id": 8,
  "method": "delete_message",
  "params": {
    "runtime": {
      "name": "plugin_chat",
      "account_id": "main"
    },
    "message": {
      "target": "room-1",
      "message_id": "msg-42"
    }
  }
}
```

必要的成功回應：

```json
{"jsonrpc":"2.0","id":8,"result":{"accepted":true}}
```

### `set_reaction`

僅在 `capabilities.reactions=true` 時呼叫。

宿主請求：

```json
{
  "jsonrpc": "2.0",
  "id": 9,
  "method": "set_reaction",
  "params": {
    "runtime": {
      "name": "plugin_chat",
      "account_id": "main"
    },
    "message": {
      "target": "room-1",
      "message_id": "msg-42",
      "emoji": "✅"
    }
  }
}
```

必要的成功回應：

```json
{"jsonrpc":"2.0","id":9,"result":{"accepted":true}}
```

規則：

- 設定或更新反應時，`emoji` 必須為字串
- `emoji: null` 表示清除該訊息的表情符號反應

### `mark_read`

僅在 `capabilities.read_receipts=true` 時呼叫。

宿主請求：

```json
{
  "jsonrpc": "2.0",
  "id": 10,
  "method": "mark_read",
  "params": {
    "runtime": {
      "name": "plugin_chat",
      "account_id": "main"
    },
    "message": {
      "target": "room-1",
      "message_id": "msg-42"
    }
  }
}
```

必要的成功回應：

```json
{"jsonrpc":"2.0","id":10,"result":{"accepted":true}}
```

### 輸入中狀態 RPC

僅在 `capabilities.typing=true` 時呼叫。

請求：

```json
{"jsonrpc":"2.0","id":11,"method":"start_typing","params":{"runtime":{"name":"plugin_chat","account_id":"main"},"recipient":"room-1"}}
```

```json
{"jsonrpc":"2.0","id":12,"method":"stop_typing","params":{"runtime":{"name":"plugin_chat","account_id":"main"},"recipient":"room-1"}}
```

必要的成功回應：

```json
{"jsonrpc":"2.0","id":13,"result":{"accepted":true}}
```

## 傳入訊息通知

外觀外掛以通知（Notification）形式推送傳入的流量：

```json
{
  "jsonrpc": "2.0",
  "method": "inbound_message",
  "params": {
    "message": {
      "sender_id": "5511",
      "chat_id": "room-1",
      "text": "hello",
      "session_key": "optional-custom-session",
      "media": ["https://example.com/a.jpg"],
      "metadata": {
        "peer_kind": "group",
        "peer_id": "room-1",
        "is_group": true,
        "typing_recipient": "room-1"
      }
    }
  }
}
```

必填欄位：

- `sender_id`
- `chat_id`
- `text`

選填欄位：

- `session_key`
- `media`
- `metadata`

驗證規則：

- `sender_id` 與 `chat_id` 必須為非空字串
- `text` 必須為字串
- 若提供 `media`，必須為非空字串陣列
- 若提供 `metadata`，必須為 JSON 物件

## 元資料慣例

`metadata` 是針對各頻道專屬語意進行自訂擴充的主要介面。

推薦鍵名：

- `peer_kind`
  穩定的通訊對象類型，例如 `dm`（私訊）、`group`（群組）、`thread`（對話串）或頻道自訂值。
- `peer_id`
  穩定的通訊對象識別碼，與 `peer_kind` 一起用於路由與連線階段隔離。
- `is_group`
  明確的群組指示標誌。
- `is_dm`
  明確的私訊指示標誌。
- `typing_recipient`
  用於發送正在輸入提示的目標識別碼。

宿主端處理行為：

- 宿主會自動將 `account_id` 注入到傳入的元資料中
- 若未提供 `session_key`，宿主會依據以下優先順序衍生產生：
  - 可用時使用 `runtime_name + account_id + peer_kind + peer_id`
  - 否則使用 `runtime_name + account_id + chat_id`
- 對於未知或外部頻道，元資料會被提昇納入對話脈絡（Conversation context）中

## 錯誤處理語意

在以下情況應使用 JSON-RPC `error` 回傳：

- 無效參數
- 不支援的方法
- 橋接器或傳輸層故障
- 外掛內部錯誤

只有在動作確實被接受並處理時，才使用 `result.accepted: true`。

建議的 JSON-RPC 錯誤代碼：

- `-32601`
  找不到方法 / 未實作
- `-32602`
  參數無效
- `-32000` 及以下
  外掛自訂的執行階段錯誤

## 逾時與監控管理

設定的 `transport.timeout_ms` 並非保證每個呼叫在每個控制路徑都能阻塞那麼久。NullClaw 內部對健全檢查與監控敏感的請求會套用更嚴格的時間上限。

維運影響：

- 當掉的外掛不會無限期卡死守護行程
- 宿主會快取並記住不支援的選用 RPC，避免反覆呼叫
- 健全檢查結果會進行短期快取，避免高頻輪詢探測

外掛應遵循以下原則：

- 迅速回應 `stop` 請求
- 確保 stdout 不被阻塞
- 盡可能避免在 JSON-RPC 主執行緒上執行耗時過長的工作

對於需要互動式登入驗證的流程（例如掃描 QR Code 或裝置配對），建議採用非同步登入模型：

- `start` 啟動背景連線/認證工作並迅速返回
- `health` 回報頻道當前是否已連線並已成功登入
- 由外掛或其配套的橋接器負責渲染 QR Code 或處理配對體驗，而不是拉長宿主控制平面的逾時限制

## 安全機制與隔離

宿主契約邊界被刻意設計得非常精簡，但外掛程式碼依然是作為本機行程執行，擁有與執行 NullClaw 之系統使用者相同的權限。

建議最佳實踐：

- 將外掛視為受信任的本機軟體，而非沙盒化隔離的不可信程式碼
- 橋接器 URL 請保持使用本機或 HTTPS 連線
- 謹慎透過 `transport.env` 或外掛專屬設定傳遞機密金鑰
- 避免將 Token 或原始使用者訊息列印至 stderr
- 外掛的持久化狀態資料僅存儲在 `runtime.state_dir` 目錄下

## CLI 與維運操作

實用指令：

```bash
nullclaw channel start external
```

啟動第一個設定的外部頻道帳號。

```bash
nullclaw channel start whatsapp_web
```

啟動執行階段名稱為 `whatsapp_web` 的已設定外部頻道帳號。

## 參考配接器

專案儲存庫中內建了橋接配接器範例：

- [`examples/whatsapp-web/nullclaw-plugin-whatsapp-web`](../../examples/whatsapp-web/nullclaw-plugin-whatsapp-web)
- [`examples/external-channel-template/nullclaw-plugin-template`](../../examples/external-channel-template/nullclaw-plugin-template)

它將來自 PR #265 的 WhatsApp Web HTTP 橋接器結構轉換為當前的 ExternalChannel JSON-RPC 協定約定。

關於 WhatsApp Web 完整的維運流程（包括橋接器驗證 vs WhatsApp 驗證、QR Code/配對歸屬以及首次執行驗證），請參閱範例 README：

- [`examples/whatsapp-web/README.md`](../../examples/whatsapp-web/README.md)

若您需要通用的外掛開發起步範本而非 WhatsApp 專用橋接器，請參閱：

- [`examples/external-channel-template/README.md`](../../examples/external-channel-template/README.md)

專案樹外的配套儲存庫：

- [nullclaw/nullclaw-channel-baileys](https://github.com/nullclaw/nullclaw-channel-baileys)
  直接基於 Node/Baileys 的外部頻道外掛，支援 QR Code 與配對碼流程。
- [nullclaw/nullclaw-channel-whatsmeow-bridge](https://github.com/nullclaw/nullclaw-channel-whatsmeow-bridge)
  獨立的 Go/whatsmeow HTTP 橋接器，具備 QR Code、配對碼與部署資產。
- `nullclaw-channel-imap-connector`
  Python IMAP/SMTP 外部頻道外掛，支援雙向電子郵件與配套信箱 CLI 流程。

上述儲存庫是放置生產級專屬頻道程式碼的推薦位置；本儲存庫內建的範例則作為參考配接器與範本。

## 外掛作者檢查清單

- 實作 `get_manifest`
- 實作 `start`、`send` 與 `stop`
- 回傳 `protocol_version: 2`
- `start` 回傳 `started: true`
- 保持 `start` 不會因 QR Code 掃描、配對與互動驗證而阻塞
- 接受的外發動作回傳 `accepted: true`
- 發送 `inbound_message` 時使用 `text` 欄位而非 `content`
- 涉及通訊對象路由時，在元資料中帶入 `peer_kind` 與 `peer_id`
- 使用 `state_dir` 存儲帳號持久化狀態
- 確保 stdout 乾淨，只輸出標準通訊協定資料

## 疑難排解

`channel start <runtime_name>` 立即失敗：

- 檢查 `transport.command` 是否存在且具備執行權限
- 驗證 manifest 是否使用 `protocol_version: 2`
- 驗證 `start.result.started` 是否存在且為 true

訊息從未進入正確的連線階段：

- 在傳入通知中帶入 `session_key`，或至少包含 `metadata.peer_kind` 與 `metadata.peer_id`
- 確保多個帳號之間沒有重複使用相同的 `runtime_name`

實際橋接器已斷線但健全狀態仍顯示綠燈：

- 實作 `health` RPC
- 除非能回報有實質意義的狀態，否則不要宣告 `capabilities.health=true`

外掛日誌干擾宿主程式運作：

- stdout 必須只包含 JSON-RPC 格式資料
- 人類可讀的偵錯日誌請一律輸出至 stderr
