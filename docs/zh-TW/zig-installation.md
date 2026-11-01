# Zig 安裝指南

## 優先使用已封裝的安裝方式

如果您已經在 macOS 或 Linux 上使用 Homebrew，最快速的途徑是直接安裝預先建置的 NullClaw 套件，不需要在本機安裝 Zig 工具鏈：

```bash
brew install nullclaw
```

只有在您想要從原始碼編譯 NullClaw，且需要精確釘選的 Zig 0.16.0 工具鏈時，才需要遵循下方的 Debian 步驟。

## Debian

以下步驟說明如何在全新安裝的 Debian 系統上，使用官方 x86_64 Linux tarball 安裝 Zig 0.16.0。
請以 root 權限執行 `apt` 指令，或在非 root 使用者下於每個指令前加上 `sudo`。

儲存庫中的 CI 與容器建置是透過 `.github/scripts/install-zig.sh` 來解析 Zig 下載資訊。
本頁面保留手動 Debian 安裝步驟，方便使用者在第一次從原始碼建置前先安裝好 Zig。

1. 更新套件清單索引：

   ```bash
   apt update
   ```

2. 安裝下載與解壓縮所需的工具：

   ```bash
   apt install -y ca-certificates wget xz-utils
   ```

3. 前往 [ziglang.org/download](https://ziglang.org/download/) 並複製 Zig 0.16.0 的下載連結。在標準的 Debian x86_64 環境中，請使用 Linux `x86_64` 版本：

   [https://ziglang.org/download/0.16.0/zig-x86_64-linux-0.16.0.tar.xz](https://ziglang.org/download/0.16.0/zig-x86_64-linux-0.16.0.tar.xz)

4. 下載 tarball 封存檔：

   ```bash
   wget https://ziglang.org/download/0.16.0/zig-x86_64-linux-0.16.0.tar.xz
   ```

5. 使用官方下載元資料中的雜湊值驗證封存檔：

   ```bash
   printf '%s  %s\n' \
     70e49664a74374b48b51e6f3fdfbf437f6395d42509050588bd49abe52ba3d00 \
     zig-x86_64-linux-0.16.0.tar.xz | sha256sum -c -
   ```

6. 解壓縮封存檔：

   ```bash
   tar -xf zig-x86_64-linux-0.16.0.tar.xz
   ```

7. 將解壓縮後的目錄加入您的 `PATH` 環境變數：

   ```bash
   export PATH="$PWD/zig-x86_64-linux-0.16.0:$PATH"
   ```

   若要在新的 shell 終端機工作階段中持續使用 Zig，請將帶有絕對路徑的 `export` 指令加入您的 shell 設定檔（例如 `~/.bashrc` 或 `~/.zshrc`）。

8. 驗證安裝的版本是否符合要求：

   ```bash
   zig version
   ```

   輸出結果必須為 `0.16.0`。
