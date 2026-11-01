# NullClaw 正體中文文件

本目錄提供面向使用者、維運人員與貢獻者的正體中文文件入口。

社群：[加入 Discord](https://discord.gg/Bfmdua22Ud)

如果您剛接觸 NullClaw，請先從這裡找到適合的閱讀路徑，再進入具體章節。

## 頁面導覽

**本頁適合誰**

- 剛接觸本專案、還不知道先閱讀哪篇文件的新使用者
- 需要在維運、開發、日常使用三條路線之間做選擇的人
- 想從正體中文總覽快速導覽至詳細章節的貢獻者

**閱讀完後下一步**

- 尚未安裝或執行：請先參閱 [安裝指南](./installation.md)
- Debian 原始碼建置還缺少 Zig：請先參閱 [Zig 安裝指南](./zig-installation.md)
- 已經安裝完成，準備連接 Model Provider / Memory / Channel：請參閱 [設定指南](./configuration.md)
- 想要快速查詢 CLI 指令：請直接前往 [指令參考](./commands.md)

**如果您是從以下位置跳轉過來**

- `README.md`：將此頁作為正體中文首頁，然後根據您的目標繼續閱讀
- [指令參考](./commands.md)：返回此處可重新選擇「新手上手 / 維運 / 開發」的閱讀路徑
- [開發指南](./development.md)：返回此處可切換為使用者或維運視角的文件

## 從何開始

### 0. 我沒有任何技術背景

如果您是第一次接觸 NullClaw、從未設定過 AI 模型、沒編輯過 JSON 檔案，或不熟悉命令列工具，請先從這裡開始：

[新手入門指南](./beginners-guide.md)

### 1. 我只想先讓它跑起來

推薦閱讀順序：

1. [安裝指南](./installation.md)
2. [設定指南](./configuration.md)
3. [使用與維運](./usage.md)
4. [指令參考](./commands.md)

### 2. 我需要部署與長期維運

重點參閱：

- [使用與維運](./usage.md)
- [安全機制](./security.md)
- [Gateway API](./gateway-api.md)
- [DingTalk 維運就緒指南](./ops/dingtalk-ops-readiness.md)
- [Lark 維運就緒指南](./ops/lark-ops-readiness.md)
- [Signal 部署指南](../../SIGNAL.md)

### 3. 我想要串接內建頻道以外的系統

重點參閱：

- [外部頻道外掛](./external-channels.md)
- [設定指南](./configuration.md)
- [使用與維運](./usage.md)
- [架構總覽](./architecture.md)

### 4. 我想要貢獻程式碼或文件

重點參閱：

- [架構總覽](./architecture.md)
- [開發指南](./development.md)
- [指令參考](./commands.md)
- [貢獻指南](../../CONTRIBUTING.md)

## 文件導覽

- [新手入門指南](./beginners-guide.md)  ← 第一次接觸 NullClaw，從這裡開始
- [安裝指南](./installation.md)
- [Zig 安裝指南](./zig-installation.md)
- [Termux 指南](./termux.md)
- [設定指南](./configuration.md)
- [使用與維運](./usage.md)
- [架構總覽](./architecture.md)
- [安全機制](./security.md)
- [Gateway API](./gateway-api.md)
- [外部頻道外掛](./external-channels.md)
- [指令參考](./commands.md)
- [開發指南](./development.md)

## 維運手冊

- [DingTalk 維運就緒指南](./ops/dingtalk-ops-readiness.md)
- [Lark 維運就緒指南](./ops/lark-ops-readiness.md)

## 重要須知（快速掌握 3 點）

1. NullClaw 目前要求精確的 **Zig 0.16.0** 版本；Debian 系統安裝方式請參閱 [Zig 安裝指南](./zig-installation.md)。
2. 預設設定檔路徑為 `~/.nullclaw/config.json`（可由 `nullclaw onboard` 自動產生）。
3. 首次上手建議先執行 `onboard --interactive` 進行互動式設定，再透過 `agent` 與 `gateway` 驗證。

## 最快速上手（3 分鐘）

```bash
brew install nullclaw
nullclaw onboard --interactive
nullclaw agent -m "hello nullclaw"
```

如果您不是透過 Homebrew 安裝，請參閱 [安裝指南](./installation.md) 查看容器映像檔或原始碼建置方式。

## 專題文件

- [安全揭露政策](../../SECURITY.md)
- [Signal 頻道部署](../../SIGNAL.md)
- [貢獻指南](../../CONTRIBUTING.md)

## 下一步

- 新使用者：請依 [安裝指南](./installation.md) → [設定指南](./configuration.md) → [使用與維運](./usage.md) 順序繼續。
- 維運 / 整合人員：先閱讀 [使用與維運](./usage.md)，再進一步查閱 [安全機制](./security.md)、[Gateway API](./gateway-api.md) 與對應的維運手冊。
- 貢獻者：請先閱讀 [開發指南](./development.md)，準備提交 Pull Request 時再參閱 [貢獻指南](../../CONTRIBUTING.md)。

## 相關頁面

- [Termux 指南](./termux.md)
- [指令參考](./commands.md)
- [架構總覽](./architecture.md)
- [安全機制](./security.md)
- [Gateway API](./gateway-api.md)
