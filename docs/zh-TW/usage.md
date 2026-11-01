# 使用與維運

本頁面聚焦於日常常用指令、背景服務模式與常見疑難排解。

## 頁面導覽

**本頁適合誰**

- 透過 CLI 或服務模式日常使用 NullClaw 的使用者
- 檢查健全狀態、重啟服務與進行變更後驗證的維運人員
- 診斷與縮小啟動、模型、頻道或閘道問題範圍的排錯人員

**閱讀完後下一步**

- 若需要超越本頁常見路徑的完整 CLI 指令集，請參閱 [指令參考](./commands.md)
- 在對外開放閘道或放寬允許清單與自主權限前，請先閱讀 [安全機制](./security.md)
- 若您的維運流程依賴配對機制或 Webhook 呼叫，請參閱 [Gateway API](./gateway-api.md)

**如果您是從以下位置跳轉過來**

- [安裝指南](./installation.md)：本頁接續於二進位執行檔安裝完成後的首次執行與檢查步驟
- [設定指南](./configuration.md)：在此透過執行階段指令與排錯步驟來驗證設定變更
- [指令參考](./commands.md)：當您需要操作流程與脈絡，而不只是單純的指令清單時，請參閱本頁

## 首次執行流程

1. 初始化設定：

```bash
nullclaw onboard --interactive
```

2. 發送測試訊息：

```bash
nullclaw agent -m "hello nullclaw"
```

3. 啟動常駐閘道服務：

```bash
nullclaw gateway
```

## 常用指令速查

| 指令 | 用途 |
|---|---|
| `nullclaw onboard --api-key sk-... --provider openrouter` | 快速設定 Provider 與 API 金鑰 |
| `nullclaw onboard --interactive` | 完整的互動式設定精靈 |
| `nullclaw onboard --channels-only` | 僅重新設定頻道與允許清單 |
| `nullclaw agent -m "..."` | 單次對話模式 |
| `nullclaw agent` | 互動式對話模式 |
| `nullclaw gateway` | 啟動常駐執行環境（預設 `127.0.0.1:3000`） |
| `nullclaw service install` | 安裝系統背景服務 |
| `nullclaw service start` | 啟動背景服務 |
| `nullclaw service status` | 檢查背景服務狀態 |
| `nullclaw service stop` | 停止背景服務 |
| `nullclaw service uninstall` | 解除安裝背景服務 |
| `nullclaw doctor` | 執行環境與配置診斷 |
| `nullclaw status` | 顯示整體系統狀態 |
| `nullclaw channel status` | 顯示頻道健全狀態 |
| `nullclaw channel start telegram` | 啟動特定頻道 |
| `nullclaw migrate openclaw --dry-run` | 模擬執行 OpenClaw 移轉 |
| `nullclaw migrate openclaw` | 正式執行 OpenClaw 移轉 |
| `nullclaw history list [--limit N] [--offset N] [--json]` | 列出對話連線階段清單 |
| `nullclaw history show <session_id> [--limit N] [--offset N] [--json]` | 顯示指定連線階段的歷史訊息 |

## 服務模式建議

對於長期運作的生產環境：

- macOS 使用 `launchctl`。
- Linux 在可用時使用 `systemd --user`；若環境有安裝支援，則降級回退使用 OpenRC 或 SysVinit。
- Windows 使用 Service Control Manager（服務控制管理員）。
- 若 Linux 環境既沒有運作正常的 `systemd --user`，也沒有支援的 OpenRC/SysVinit，服務子指令將會失敗；此時請改以前景執行 `nullclaw gateway` 或使用其他行程管理工具（如 supervisor/pm2）。

```bash
nullclaw service install
nullclaw service start
nullclaw service status
```

進階機密資料載入方式：

- 產生的服務啟動腳本在執行 `nullclaw gateway` 之前，會檢查是否存在可執行的 `~/.nullclaw/service-env` 輔助程式。
- 您可利用該輔助程式透過 `dotenvx`、`sops` 或其他本機機密載入工具注入機密資訊，無需手動修改已安裝的服務 unit 或腳本。

進行重大設定變更後，請重啟服務：

```bash
nullclaw service stop
nullclaw service start
```

## 閘道與配對

- 預設閘道位址：`127.0.0.1:3000`
- 建議設定：維持 `gateway.require_pairing = true`
- 若需要公開存取，強烈建議使用網路通道（Tunnel）或反向代理（Reverse Proxy），而非直接綁定公開 IP
- `/pair` 端點僅限 POST 請求，使用 `X-Pairing-Code` 標頭驗證；在連續多次錯誤嘗試後會進行速率限制或暫時鎖定

健全狀態檢查：

```bash
curl http://127.0.0.1:3000/health
```

## 常見問題（FAQ）

### 1) 啟動時發生設定錯誤

處理步驟：

1. 執行 `nullclaw doctor` 查看詳細錯誤訊息。
2. 對照 `config.example.json` 確認設定鍵名稱與巢狀層級是否正確。
3. 驗證 JSON 語法格式（檢查逗號、引號、括號是否對齊）。

### 2) 模型呼叫失敗 (401/403)

常見原因：

- API 金鑰無效或已過期。
- Provider 設定不符（例如：選定的 Provider 與填入的金鑰不匹配）。
- 模型路由格式或字串無效。

檢查方式：

```bash
nullclaw status
```

然後重新執行引導設定：

```bash
nullclaw onboard --interactive
```

### 3) 頻道未收到任何訊息

檢查項目：

- `channels.<name>.accounts.*` 中的 Token、Webhook 與帳號設定。
- 頻道專屬的允許清單或過濾限制（`allow_from`、`group_allow_from`、`require_mention` 等設定）。請注意：空的 `allow_from` 並不等於全面拒絕。
- 執行 `nullclaw channel status` 檢查頻道健全輸出。
- 針對 DingTalk（釘釘）專屬的串流與回覆目標檢查，請參閱 [DingTalk 維運就緒指南](./ops/dingtalk-ops-readiness.md)。

### 4) 閘道已啟動但無法從外部連線存取

常見原因：

- 仍綁定在 `127.0.0.1` 本機迴路位址。
- 尚未設定網路通道（Tunnel）或反向代理。
- 防火牆連接埠未開啟。

### 5) Provider 回傳 429 / "rate limit exceeded"（超出速率限制）

常見原因：

- 低配額的程式碼方案可能在普通聊天仍正常時，拒絕呼叫大量工具的 Agent 回合。
- 針對當前 Provider 方案的重試機制過於激進。
- 當主要 Provider 達到配額或速率上限時，未設定降級備用（Fallback）Provider。

檢查方式：

- 前景執行時，使用 `nullclaw agent --verbose` 啟動。
- 服務模式下，檢查 `~/.nullclaw/logs/daemon.stdout.log` 與 `~/.nullclaw/logs/daemon.stderr.log`。
- 執行 `nullclaw status` 確認當前的 Provider/Model 組合。

若方案有效但較脆弱，可採取保守的可靠性設定：

```json
{
  "reliability": {
    "provider_retries": 1,
    "provider_backoff_ms": 3000,
    "fallback_providers": ["openrouter"]
  }
}
```

若您同一個 Provider 擁有多組金鑰，可加入 `reliability.api_keys` 讓 NullClaw 自動輪替。

### 6) 本機 Ollama 模型提示無法存取 `scheduler_tool`

通常代表的原因：

- NullClaw 的標準工具名稱為 `schedule`。
- 某些由 Ollama 託管的本機模型會輸出 `scheduler_tool` 或 `schedule_tool` 別名。
- 目前的 NullClaw 建置版本已會在派送工具前自動將這些 Ollama 別名正規化回 `schedule`。

檢查方式：

- 確認您執行的版本包含 Ollama 工具別名正規化修正。
- 若排程相關名稱仍出現 `Unknown tool`，請加上 `nullclaw agent --verbose` 重新執行排查。
- 若釘選在舊版二進位檔，請在修改排程設定前先升級 NullClaw。此問題通常是工具名稱偏差，而非排程器遭到停用。

## 設定變更後檢查清單

修改設定後建議依序執行：

```bash
nullclaw doctor
nullclaw status
nullclaw channel status
nullclaw agent -m "self-check"
```

涉及閘道場景時：

```bash
nullclaw gateway
curl http://127.0.0.1:3000/health
```

## 下一步

- 查閱 [指令參考](./commands.md) 了解進階 CLI 操作與完整指令目錄
- 在從純本地端運作切換為對外公開存取前，請詳閱 [安全機制](./security.md)
- 當維運檢查包含配對流程或 Webhook 整合時，請參閱 [Gateway API](./gateway-api.md)

## 相關頁面

- [安裝指南](./installation.md)
- [設定指南](./configuration.md)
- [指令參考](./commands.md)
- [安全機制](./security.md)
