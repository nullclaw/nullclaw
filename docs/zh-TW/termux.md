# Termux 指南

本指南介紹在 Android / Termux 環境下執行 NullClaw 的具體實踐路徑。

## 頁面導覽

**本頁適合誰**

- 直接在 Android 裝置上的 Termux 內執行 NullClaw 的使用者
- 記錄行動端安裝或進行疑難排解的貢獻者
- 評估 Termux 是否足以滿足其工作負載的維運人員

**閱讀完後下一步**

- 若需要了解整體的安裝方式對照表，請先參閱 [安裝指南](./installation.md)
- 執行檔建置完成後，請參閱 [設定指南](./configuration.md)
- 當準備好測試 `agent` 或 `gateway` 時，請參閱 [使用與維運](./usage.md)

## 預期運作表現

Termux 最適合用於：

- 前景模式執行
- 手動功能測試
- 受限環境下的本地部署

Termux 較不適合用於：

- 直接在手機本機端進行長期高負載模型推論
- 必須承受 Android 系統記憶體回收壓力的背景常駐服務

如果 Android 系統因記憶體不足而強制結束該行程，這是 Android / Termux 的系統限制，不一定是 NullClaw 的程式錯誤。

## 前置需求

- **精確的 Zig 0.16.0 版本**
- Git
- 足夠的本機儲存空間以容納專案儲存庫與建置快取

建置前請務必驗證 Zig 版本：

```bash
zig version
```

輸出結果必須為 `0.16.0`。

## Termux 原生建置

```bash
pkg update
pkg install git zig
git clone https://github.com/nullclaw/nullclaw.git
cd nullclaw
zig version
zig build -Doptimize=ReleaseSmall
./zig-out/bin/nullclaw --help
```

注意事項：

- 在 Termux 原生建置時，通常**不需要**指定 `-Dtarget`。
- 建議使用 `-Doptimize=ReleaseSmall` 或 `-Doptimize=ReleaseFast`。
- **請勿**使用舊範例中的舊版語法 `-Drelease-fast`。

## 低相依性建置

若在 Termux 中下載或編譯 SQLite 失敗，可先嘗試較輕量的記憶體引擎組合：

```bash
zig build -Doptimize=ReleaseSmall -Dengines=base
```

`-Dengines=base` 會保留 `markdown,memory,api,none`，並完全略過 SQLite。

您也可以明確指定要編譯的引擎：

```bash
zig build -Doptimize=ReleaseSmall -Dengines=markdown,memory
```

在規格較小的 Android 裝置上，這通常是最佳的起步里程碑。

## 常見錯誤：`build.zig.zon` "expected string literal"

若看到如下錯誤訊息：

```text
build.zig.zon:2:14: error: expected string literal
```

通常原因是 Zig 工具鏈版本不符，而非 NullClaw 原始碼的問題。

檢查步驟：

1. 執行 `zig version`。
2. 確認其輸出為 `0.16.0`。
3. 若版本不符，請先更換 Zig 套件或執行檔後再重新嘗試。

請勿為了解決舊版 Zig 的問題而修改本地的 `build.zig.zon`。本專案嚴格釘選於 Zig 0.16.0。

## 初次執行檢查

二進位執行檔建置完成後，請先驗證兩個最簡單的進入點：

```bash
./zig-out/bin/nullclaw agent
./zig-out/bin/nullclaw gateway --host 127.0.0.1 --port 3001
```

在嘗試撰寫包裝指令碼、啟動器或背景自動化前，請先以前景模式確認其能正常執行。

## 為 Android 進行交叉編譯

若您在其他電腦上為 Termux / Android 裝置建置，需要同時提供 Zig target 與 Android libc/sysroot 檔案：

```bash
zig build -Dtarget=aarch64-linux-android.24 -Doptimize=ReleaseSmall --libc /path/to/android-libc-aarch64.txt
```

常見目標架構：

- `aarch64-linux-android.24`
- `arm-linux-androideabi.24` 搭配 `-Dcpu=baseline+v7a`
- `x86_64-linux-android.24`

請使用與裝置硬體架構相符的目標。
從 Android NDK 產生 `--libc` 檔案的完整範例請參閱 [`.github/workflows/release.yml`](../../.github/workflows/release.yml)。

## 實用建議

- 先達成小目標：成功編譯出執行檔、執行 `--help`，接著測試 `agent` 或 `gateway`。
- 若裝置記憶體（RAM）較有限，優先使用遠端雲端模型 Provider。
- 若需要穩定長期的工作負載，Termux 更適合充當測試平台，而非最終的主機環境。

## 相關頁面

- [安裝指南](./installation.md)
- [設定指南](./configuration.md)
- [使用與維運](./usage.md)
- [指令參考](./commands.md)
