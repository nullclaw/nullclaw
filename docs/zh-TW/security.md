# 安全機制

NullClaw 遵循「預設安全」（Secure-by-default）原則：預設僅綁定本地迴路、要求配對認證、沙盒隔離環境以及最小權限原則。

## 頁面導覽

**本頁適合誰**

- 強化本地端或透過通道暴露之 NullClaw 部署環境的維運人員
- 審查設定或執行階段變更是否放寬了信任邊界的審查者
- 涉及閘道（Gateway）、工具（Tools）、沙盒（Sandbox）或安全暴露敏感路徑的貢獻者

**閱讀完後下一步**

- 若需要此處總結的控制項背後的具體設定鍵，請參閱 [設定指南](./configuration.md)
- 如果您的安全性審查包含配對、Bearer Token 或 Webhook，請參閱 [Gateway API](./gateway-api.md)
- 進行安全相關設定變更後，請參閱 [使用與維運](./usage.md) 執行日常驗證檢查

**如果您是從以下位置跳轉過來**

- [使用與維運](./usage.md)：本頁說明閘道與服務建議背後的安全強化背景
- [設定指南](./configuration.md)：當某個設定鍵具有安全性影響並需要原則層級的解釋時，請參閱本頁
- [架構設計](./architecture.md)：當子系統設計決策跨越安全敏感邊界時，返回本頁查閱

## 基礎安全控制項

| 項目 | 狀態 | 實作機制 |
|---|---|---|
| 閘道預設不對外公開暴露 | 已啟用 | 預設綁定 `127.0.0.1`；未設定通道或明確覆寫前拒絕綁定公開 IP |
| 要求配對認證 | 已啟用 | 一次性 6 位數配對碼，透過 `POST /pair` 進行交換 |
| 檔案系統存取範圍限制 | 已啟用 | 預設 `workspace_only = true` |
| 具備通道感知之對外暴露 | 已啟用 | 預期透過 Tailscale / Cloudflare / ngrok / 自訂通道進行公開存取 |
| 沙盒隔離 | 已啟用 | 自動選擇 Landlock / Firejail / Bubblewrap / Docker |
| 機密加密儲存 | 已啟用 | 靜態憑證資料採用 ChaCha20-Poly1305 加密儲存 |
| 資源上限限制 | 已啟用 | 可設定記憶體、CPU 與子行程數量上限 |
| 審計日誌 | 已啟用 | 選用的審計軌跡，支援保留原則設定 |

## 隱私資訊遮蔽邊界

當啟用個資遮蔽（PII Redaction）時，NullClaw 會在呼叫 Model Provider、本機連線階段持久化、記憶體自動儲存、系統診斷與向量嵌入同步之前，將偵測到的敏感資訊替換為確定性的佔位符（例如 `[EMAIL_1]`、`[PHONE_1]` 或 `[CARD_1]`）。

可重複使用的遮蔽器預設為單向運作：它使用 HMAC-SHA256 指紋為數值建立索引，不保留原始明文。Agent 在其個別對話遮蔽器中採用選用的記憶體內反向對照表，因此可以在同主體、單一使用者的顯示路徑中還原佔位符。共用頻道、群組和對話串連線階段則會在傳出的回應中保留佔位符。工具參數預設保留字面佔位符；這能防止 Provider 的輸出成為 Provider 到 Tool 之間的資料外洩管道。反向對照表僅存在於行程的記憶體中，具有容量上限，並會隨著對話結束而重設，絕不會被寫入持久化記憶體、歷史紀錄、JSONL 匯出或診斷資料中。

該遮蔽器是輕量級的文字掃描器，而非完整的 DLP/OCR 引擎。它涵蓋電子郵件、電話號碼、符合 Luhn 演算法的信用卡號、錨定格式的護照/身分證字號，以及 Token/機密特徵等常見文字形式。二進位圖片內容、OCR 文字、EXIF 元資料與未支援的特定地區文件格式均不在其邊界之內，除非先有其他工具將其擷取為純文字。

## 受管制的記憶體工作流程

當記憶體資料需要作為資料科學產出物時，請使用 `nullclaw memory export-jsonl`。該指令輸出具有穩定結構的 JSONL，且預設排除引導/自動儲存的內部項目。內容預設會進行個資遮蔽。僅在受信任的本機環境內匯出時，才使用 `--include-pii`；舊有的 `--redact-pii` 旗標仍作為相容性的 no-op 被接受。

在進行清理工作之前，請先使用 `nullclaw memory hygiene-report`。該指令永遠為模擬執行（Dry-run）：它會報告完全重複與正規化重複的群組，不會刪除、覆寫或重新索引任何記憶體項目。

## 隨選匿名化工具

`anonymize_text` 工具為 Agent 提供了相同的輕量級遮蔽功能，用於單次純文字片段。它接受必填的 `text` 欄位以及選填的 `redact_email`、`redact_phone`、`redact_card`、`redact_id` 與 `redact_tokens` 布林值。所有類別預設皆啟用；明確停用的類別將保持原樣傳遞。

面向模型的 `sqlite_query` 工具回傳的結果永遠經過遮蔽。原始敏感的 SQLite 輸出絕不會透過 Agent 工具介面暴露。此外，它還會拒絕常見的文字轉換/編碼函式（例如 `hex(...)` 與 `substr(...)`），因為這些函式會將個資轉換為查詢執行後文字遮蔽器無法還原的型態。

每次呼叫皆使用全新的單向遮蔽器，因此佔位符計數器在該次呼叫內會重新從 `[EMAIL_1]` / `[PHONE_1]` 開始計算，工具返回後不會保留任何明文反向對照表。在將使用者提供的文字放入工單、Notebook、日誌、匯出檔案或不需要原始機密值的下游工具前，請先使用此工具。該工具僅支援純文字，輸入限制為 256 KiB；不會檢查二進位圖片內容、OCR 文字或 EXIF 元資料。

## 頻道允許清單

- 在採用允許清單機制的頻道上，空的 `allow_from` 會拒絕所有傳入訊息。
- 若需要私密機器人，請設定明確的使用者 ID / OpenID。
- `allow_from: ["*"]`：允許所有來源傳入（高風險）。
- 其他情況：預期為完全相符的允許清單或特定頻道的降級備用/群組原則行為。

## 配對與 Webhook 驗證邊界

- `/pair` 僅限 POST 請求，並要求帶有 `X-Pairing-Code` 標頭。
- 連續多次無效的配對嘗試將觸發速率限制與暫時鎖定。
- 當啟用 A2A（Agent-to-Agent）時，`/.well-known/agent.json` 與 `/.well-known/agent-card.json` 為公開探索文件。
- 保持 `gateway.require_pairing = true` 會使 `/webhook`、`/a2a` 與 `/media/transcribe` 受到 Bearer Token 驗證保護；停用配對會移除本地綁定上的 Bearer 檢查。
- Telegram 的 Webhook 傳送要求 `X-Telegram-Bot-Api-Secret-Token` 與 `channels.telegram.accounts.<id>.webhook_secret` 相符。
- 特定頻道的傳入 Webhook 保留其各自的驗證或簽章規則，不應被誤認為一律使用閘道 Bearer 驗證。

## Nostr 專屬規則

- 即使 `dm_allowed_pubkeys` 限制更嚴格，`owner_pubkey` 永遠被允許。
- 私鑰以加密形式存儲（`enc2:`），僅在頻道運作期間於記憶體中解密。

## 推薦安全設定

```json
{
  "gateway": {
    "host": "127.0.0.1",
    "port": 3000,
    "require_pairing": true,
    "allow_public_bind": false
  },
  "autonomy": {
    "level": "supervised",
    "workspace_only": true,
    "max_actions_per_hour": 20
  },
  "security": {
    "sandbox": { "backend": "auto" },
    "audit": { "enabled": true, "retention_days": 90 }
  }
}
```

## Shell 環境變數

預設情況下，只有最小限度的安全環境變數（`PATH`、`HOME`、`TERM`、`LANG`、`LC_ALL`、`LC_CTYPE`、`USER`、`SHELL`、`TMPDIR`）會傳遞給 Shell 子行程。這可避免洩漏 API 金鑰與機密憑證（CWE-200）。

### 經過路徑驗證的環境變數

某些部署會透過磁碟區掛載注入工具（例如 Kubernetes 中的 toolbox init container）。這些工具可能需要諸如 `LD_LIBRARY_PATH` 等環境變數來尋找共用函式庫，但無條件傳遞 `LD_LIBRARY_PATH` 具有安全性風險（函式庫注入攻擊）。

`tools.path_env_vars` 設定允許指定**值為平台路徑清單**（Unix 上為 `:`，Windows 上為 `;`）的環境變數。在將變數傳遞給子行程前，每個路徑元件都會針對沙盒進行驗證：

1. 每個路徑元件都必須是絕對路徑
2. 每個路徑元件都透過 `realpath` 進行解析（正規化並解析符號連結）
3. 每個路徑元件都必須位於工作區內或 `allowed_paths` 清單中
4. 系統黑名單（`/etc`、`/usr/lib`、`/bin` 等）一律予以拒絕

如果**任何**元件未通過驗證，整個環境變數將被捨棄。

```json
{
  "autonomy": {
    "allowed_paths": ["/opt/tools"]
  },
  "tools": {
    "path_env_vars": ["LD_LIBRARY_PATH", "PYTHONHOME", "NODE_PATH"]
  }
}
```

透過上述設定，當容器環境中設定了 `LD_LIBRARY_PATH=/opt/tools/usr/lib:/opt/tools/lib` 時，Shell 工具會對照 `/opt/tools`（透過 `allowed_paths`）驗證這兩個路徑元件並放行該變數。若是攻擊者控制的值（例如 `/tmp/evil:/opt/tools/lib`），由於 `/tmp/evil` 不在工作區或允許路徑中，將會被拒絕。

## 高風險設定

以下設定會大幅放寬信任邊界，應僅在受控環境下使用：

- `autonomy.level = "full"`
- `autonomy.level = "yolo"`
- `allowed_commands = ["*"]`
- `allowed_paths = ["*"]`
- `block_high_risk_commands = false` — 允許具破壞性的指令（`rm`、`sudo`、`dd`、`mkfs` 等）
- `block_medium_risk_commands = false` — 允許中風險指令，包括網路/傳輸指令（`curl`、`wget`、`nc`、`scp` 等）以及本機變更指令（如 `git commit`、`npm install`、`touch`）
- `gateway.allow_public_bind = true`

## 工作區機密審計

`nullclaw workspace audit` 會掃描工作區、暫存區 Git diff 或 Git 修訂版本範圍中潛在的機密外洩。偵測程序完全在本地機器上執行，並輸出結構穩定的 JSON 結果，非常適合與 CI 流程整合。

### 偵測項目

| 偵測器 | 來源特徵 |
|---|---|
| 已知 Token 前綴特徵碼 | `AKIA…`、`ghp_`、`gho_`、`ghs_`、`glpat-`、`xoxb-`、`xoxp-`、`sk-`、`sk-proj-` 等 |
| 基於評分的賦值比對器 | 將 `KEY=value` / `key: value` 解析為具名元件，並對照機密關鍵字字典進行評分 |
| 格式偵測器 | `-----BEGIN PRIVATE KEY-----` PEM 區塊；嵌入於 URL 中的認證資訊（`scheme://user:pass@host/...`） |
| 高熵字串巡檢器 | 長度 ≥ 16 個字元且香農熵（Shannon Entropy）≥ 4.0 的 Token 狀字串（排除 UUID、Git commit 雜湊與佔位文字） |

結束碼遵循 `--fail-on <none\|medium\|high\|critical>`（預設為 `high`）。可搭配 `--json` 用於 CI 管線。

### 選用之 LLM 輔助篩檢

`--llm-triage` 旗標提供選用的第二階段，使用 Agent 設定的 LLM Provider 對發現進行分類。分類器接收**保護隱私的信封資料**，絕不包含原始機密數值：

| 包含在信封中 | 不包含在信封中 |
|---|---|
| `variable_name`、`file_path`、`extension`、`detector` | 機密數值本身 |
| `token_type_fingerprint`（確定性的本地比對） | 機密的任何子字串 |
| `length`、`charset`、`entropy` | 機密周圍的該行完整內容 |
| 遮蔽後的該行上下文（如 `KEY=<SECRET:len=40,charset=base64url,entropy=5.3>`） | 非標準的周邊字詞 |
| 透過 ~60 個標準安全/服務詞彙白名單過濾出的 `nearby_keywords` | 客戶名稱、內部主機名稱、業務識別碼 |
| 確定性旗標：`is_test_path`、`is_example_file`、`is_in_comment`、`is_in_docstring` | LLM 對這些旗標的推論 |

信封結構具有版本控管（`schema_version: "1"`），且每個信封皆帶有 SHA-256 的 `envelope_hash` 以供追溯。

三種模式：

- `--llm-triage off`（預設）— 不執行任何 LLM 動作；行為與基準掃描完全一致。
- `--llm-triage dry-run` — 僅印出「即將」發送的信封內容（輸出至 stderr），不進行任何網路呼叫。在啟用此功能前，可用此模式確認有哪些資訊會離開本機。
- `--llm-triage external` — 透過已設定的 Provider vtable 發送信封。優先使用 `workspace_audit.llm_triage.{provider,model}`，其次使用設定的主要 Provider/Model，除非被 `--llm-provider` / `--llm-model` 覆寫。當 Provider 為本地服務（例如 Ollama）時，信封內容完全不會離開本機。

若想將審計篩檢固定至較小或本地的模型而不變更一般的 Agent 模型，可設定：

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

此設定本身不會自動啟用外部 LLM 呼叫；維運人員仍必須傳入 `--llm-triage external`。CLI 旗標 `--llm-provider`、`--llm-model` 與 `--llm-max-calls` 可為單次執行覆寫這些設定值。未知的 Provider 名稱會被拒絕（除非該 Provider 明確設定了 `models.providers.<name>.base_url`），因此輸入錯誤不會悄悄地將審計信封路由到備用 Provider。

每次 `external` 請求都會附加記錄到 `<config-dir>/audit-log.jsonl` 中。NullClaw 會在 LLM 呼叫前寫入包含信封內容的 `sent` 事件，並在收到回應後寫入以 `envelope_hash` 為鍵值的 `verdict` 判定事件。此日誌僅可附加寫入，用於事後驗證發送了哪些元資料。

### 維運人員注意事項

- 預設 `--llm-triage off` 表示現有掃描行為不變。僅在誤報篩檢成為負擔時才明確啟用。
- 對於注重隱私的部署，在啟用 `--llm-triage external` 之前，請將 `workspace_audit.llm_triage.provider` 釘選至 `ollama`（或其他純本地 Provider）。
- 判定結果僅供參考：`false_positive`（誤報）決策會捨棄該發現；`real_secret`（真實機密）決策可能會調整嚴重程度。第一階段的確定性偵測器對於是否呈現候選項目仍具決定權。

## 下一步

- 在套用本頁列出的任何高風險設定前，請先檢閱 [設定指南](./configuration.md)
- 當需要端點層級的身分驗證與對外暴露細節時，請參閱 [Gateway API](./gateway-api.md)
- 修改閘道、頻道或自主權限設定後，請執行 [使用與維運](./usage.md) 中的檢查步驟

## 相關頁面

- [設定指南](./configuration.md)
- [使用與維運](./usage.md)
- [Gateway API](./gateway-api.md)
- [架構設計](./architecture.md)
