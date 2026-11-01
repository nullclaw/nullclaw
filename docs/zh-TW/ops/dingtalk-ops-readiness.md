# DingTalk 維運就緒指南

本頁面說明 DingTalk（釘釘）頻道的專屬驗證流程，以及當系統「仍可發送訊息但無法接收傳入事件」時的最快除錯路徑。

## 頁面導覽

**本頁適合誰**

- 驗證全新 DingTalk 部署環境的維運人員
- 診斷未收到傳入訊息或頻道狀態不健全的排錯人員
- 判斷問題屬於設定偏差、舊版執行檔或釘釘端傳送問題的維護者

**閱讀完後下一步**

- 關於通用的服務與日誌處理流程，請參閱 [使用與維運](../usage.md)
- 關於主設定檔的設定脈絡，請參閱 [設定指南](../configuration.md)
- 在放寬 `allow_from` 限制前，請先閱讀 [安全機制](../security.md)

## 健全狀態判定準則

- 目前版本會將 DingTalk 作為閘道迴路頻道（Gateway-loop channel）啟動。在啟動日誌中會顯示 `dingtalk gateway started`，而非 `dingtalk started (send-only)`。
- 頻道健全狀態僅在執行環境正在運作且 DingTalk Stream WebSocket 連線成功時才為 true。
- 即使傳入傳送中斷，外發回覆可能仍能透過新鮮的連線階段 Webhook 目標成功發送，因此「能發不能收」通常代表 Stream 接收路徑有問題，而非回覆路徑故障。

## 行前檢查清單

1. 確認您執行的是最新建置版本。若日誌仍顯示 `dingtalk started (send-only)`，請先升級。
2. 檢查 `channels.dingtalk.accounts.<id>.client_id` 與 `client_secret` 是否來自同一個釘釘應用程式。
3. 檢查 `allow_from` 不為空。`allow_from: []` 會拒絕所有傳入訊息。
4. 使用 `nullclaw gateway` 啟動執行環境，並確認 `nullclaw channel status` 顯示 DingTalk 處於健全狀態。
5. 若懷疑憑證有問題，執行 `nullclaw --probe-channel-health --channel dingtalk --account <id>` 驗證 Token 取得流程。

## 若始終收不到傳入訊息

1. 確認釘釘應用程式已設定為 Stream 模式傳入。目前的執行環境透過釘釘的閘道連線 API 建立 WebSocket；僅設定外發機器人是不夠的。
2. 確認應用程式已訂閱您預期接收的訊息事件。若釘釘從未發送這些回呼，NullClaw 便無從接收。
3. 以前景模式執行，並在重啟前擷取第一筆釘釘錯誤日誌。最關鍵的日誌訊息包括 `dingtalk websocket cycle failed`、`dingtalk websocket read failed` 與 `dingtalk envelope handling failed`。
4. 使用明確列於 `allow_from` 中的發送者重新測試。若未通過允許清單比對，表現為「訊息被忽略」，而非連線傳輸失敗。

## 回覆目標與降級備用行為

- 新鮮的回覆目標會使用傳入事件附帶的 `sessionWebhook` URL。
- 若群組回覆目標過期，NullClaw 可利用快取的對話 ID 降級回退使用釘釘 AI 互動 API。
- 私訊回覆目標不具備群組降級機制；一旦連線階段 Webhook 過期，需要有新的傳入事件或主動發送目標。
- 任意的 `https://...` Webhook 目標會被刻意拒絕，且目前外發訊息尚未支援多媒體負載。

## 推薦驗證順序

```bash
nullclaw doctor
nullclaw status
nullclaw channel status
nullclaw gateway
```

接著從已允許的發送者發送一則釘釘訊息，並在重啟任何服務之前，先檢查第一筆出現的執行階段錯誤。
