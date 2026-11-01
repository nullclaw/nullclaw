# 開發指南

本頁面面向專案貢獻者。目標是協助您快速建置本地開發環境、進行目標明確的修改、驗證程式碼，並在毫無疑惑的情況下提交 Pull Request（PR）。

## 頁面導覽

**本頁適合誰**

- 正在準備本地開發環境的貢獻者
- 在開啟或審查 PR 之前驗證變更的維護者
- 檢查儲存庫工作流程與驗證基準的文件或程式碼作者

**閱讀完後下一步**

- 在修改不熟悉的子系統之前，請先參閱 [架構設計](./architecture.md)
- 如果您的變更會影響 CLI 行為或說明文件，請參閱 [指令參考](./commands.md)
- 若需要查看整體英文/多語系說明文件地圖，請參閱 [首頁](./README.md)

**如果您是從以下位置跳轉過來**

- [首頁](./README.md)：本頁專注於貢獻者專屬的設定與驗證流程
- [指令參考](./commands.md)：當 CLI 變更同時需要工作流程、測試或 PR 指引時，請參閱本頁
- `AGENTS.md`：本頁提供日常貢獻者具體實踐的檢查清單

## 開始修改前須知

- 本專案的開發與測試皆釘選於 **Zig 0.16.0**。若您在 Debian 系統上需要安裝 Zig，請參閱 [Zig 安裝指南](./zig-installation.md)。
- 在修改程式碼前，請務必先閱讀 `AGENTS.md`。
- 若需要更多專案背景脈絡、驗證規則或子系統指引，請閱讀 `CLAUDE.md`。
- 若您使用儲存庫的 Flake，`nix build` 與 `nix develop` 亦皆釘選於 **Zig 0.16.0**。

請先檢查您的 Zig 版本：

```bash
zig version
```

輸出結果必須為 `0.16.0`。

## 本地建置與測試

```bash
zig build
zig build -Doptimize=ReleaseSmall
zig build test --summary all
```

在為程式碼變更提交 PR 之前，至少必須執行：

```bash
zig build test --summary all
```

## 常見建置旗標

```bash
zig build -Dchannels=telegram,cli
zig build -Dengines=base,sqlite
zig build -Dtarget=x86_64-linux-musl
zig build -Dversion=2026.3.1
```

說明：

- `channels`：限制編譯進執行檔的頻道實作
- `engines`：限制建置中包含的記憶體儲存引擎
- `target`：交叉編譯的目標架構三元組（Target Triple）
- `version`：覆寫內嵌的版本字串（預設為 `dev`；發行流程會自動注入 Git 標籤）

## 推薦工作流程

1. 先閱讀目標模組程式碼與相鄰的單元測試。
2. 保持每個 PR 專注於單一功能或問題修復。
3. 在同一個變更中同步更新文件與測試。
4. 在開啟 PR 之前完整執行測試驗證。

## 說明文件同步

若您的修改會影響使用者、維運人員或貢獻者，請在同一個 PR 中同步更新相關文件：

- 專案首頁：`README.md`
- 英文文件：`docs/en/`
- 簡體中文文件：`docs/zh/`
- 正體中文文件：`docs/zh-TW/`
- 安全政策：`SECURITY.md`
- 專題部署指南：`SIGNAL.md`
- 貢獻指南：`CONTRIBUTING.md`

文件撰寫原則：

- 以任務為導向
- 方便複製貼上指令
- 與 `src/main.zig` 及目前的設定檔結構（Schema）保持一致
- 當受影響對象涵蓋不同語言時，請同步更新英文與中文文件

## Git Hooks

在每個複製的儲存庫中啟用一次 hooks 設定：

```bash
git config core.hooksPath .githooks
```

包含的 hooks：

- `pre-commit`：執行 `zig fmt --check src/`
- `pre-push`：執行 `zig build test --summary all`

## PR 前的驗證工作

### 純文件變更

建議執行：

```bash
git diff --check
```

同時手動檢查所有相對連結、路徑與指令範例是否正確。

### 程式碼變更

必須執行：

```bash
zig build test --summary all
```

### 發行相關變更

額外執行：

```bash
zig build -Doptimize=ReleaseSmall
```

## PR 撰寫指引

PR 說明應清楚闡述：

1. 修改了什麼
2. 為什麼要做這項修改
3. 執行了哪些驗證測試
4. 是否存在潛在風險或後續工作

建議範本：

```text
## Summary
- ...

## Validation
- zig build test --summary all

## Notes
- ...
```

## 高頻修改路徑

| 路徑 | 用途 |
|---|---|
| `src/main.zig` | CLI 指令路由分發 |
| `src/config.zig` | 設定檔載入與環境變數覆寫 |
| `src/gateway.zig` | 閘道服務與 Webhooks |
| `src/security/` | 安全機制與沙盒隔離 |
| `src/providers/` | AI 模型 Provider 實作 |
| `src/channels/` | 訊息傳遞頻道實作 |
| `src/tools/` | 工具實作 |
| `src/memory/` | 記憶體後端與檢索機制 |

## 延伸閱讀

- 架構設計：`docs/zh-TW/architecture.md`
- 指令參考：`docs/zh-TW/commands.md`
- 貢獻指南：`CONTRIBUTING.md`
- 工程規範：`AGENTS.md`

## 下一步

- 在修改深入的執行環境、安全機制或 Provider 程式碼前，請先閱讀 [架構設計](./architecture.md)
- 當變更涉及 CLI 介面或範例時，請查閱 [指令參考](./commands.md)
- 準備撰寫最終 PR 說明與進行審查流程前，請詳閱 [CONTRIBUTING.md](../../CONTRIBUTING.md)

## 相關頁面

- [首頁](./README.md)
- [安裝指南](./installation.md)
- [設定指南](./configuration.md)
- [指令參考](./commands.md)
