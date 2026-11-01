# Lark 維運就緒指南

本指南定義 Lark/Feishu（飛書）頻道的專屬維運檢查規範。

## 健全狀態判定語意

- WebSocket 模式：僅在「執行中（running）」且「已連線（connected）」兩者皆為 true 時，才判定為健全。
- Webhook 模式：當執行環境處於活躍狀態且回呼路徑（Callback path）可存取時，判定為健全。

## 身分驗證與權限

1. 驗證 Tenant Access Token 的取得與定期更新行為。
2. 凡業務代碼（Business Code）非 0 者，一律視為維運故障。
3. 遇到權限或存取範圍（Scope）錯誤時，應立即排查處理。

## `error.LarkApiError` 快速排錯

1. 執行 `nullclaw doctor` 確認頻道設定結構正確無誤。
2. 啟動後執行 `nullclaw channel status`，確認頻道是否處於「運作中但已斷線」狀態。
3. 若反覆出現 `warning(lark): lark websocket cycle failed: error.LarkApiError`，通常原因為以下之一：
   - 缺少 Lark/Feishu 應用程式所需的權限或 Scopes
   - 選錯了區域端點（`use_feishu` 設定）
   - WebSocket 回呼佈署設定失敗
4. 若舊版 Linux 建置在輸出穩定重連日誌前即當機，請先升級版本再繼續進行權限排查。

## 事故處理步驟

1. 至 Feishu/Lark 開發者後台檢查應用程式權限與 Scopes。
2. 驗證回呼端點與 WebSocket 路徑的連線可用性。
3. 確認發送者允許清單（`allow_from`）與群組提及（@mention）行為設定。
4. 唯有在記錄並捕獲根本原因後，才重啟頻道 Worker。

## SLO 監控指標

- `auth_fail_total`（驗證失敗總數）
- `reconnect_total`（重新連線總數）
- `outbound_send_fail_total`（外發訊息失敗總數）
- `healthcheck_fail_total`（健康檢查失敗總數）
