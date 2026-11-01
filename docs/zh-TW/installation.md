# 安裝指南

本指南說明 macOS、Linux 與 Windows 系統的主流安裝方式。

## 頁面導覽

**本頁適合誰**

- 準備在本地機器上安裝 NullClaw 的初次使用者
- 在套件安裝、容器部署與原始碼建置之間做選擇的維運人員
- 深入設定前驗證基礎執行環境的貢獻者

**閱讀完後下一步**

- 當執行檔安裝完成並已加入 `PATH` 後，請參閱 [設定指南](./configuration.md)
- 當準備好執行初次指令與以服務模式啟動時，請參閱 [使用與維運](./usage.md)
- 在深入設定前若需查看整體說明文件地圖，請參閱 [首頁](./README.md)

**如果您是從以下位置跳轉過來**

- [首頁](./README.md)：選定安裝方式後，本頁是具體的首次安裝執行路徑
- [指令參考](./commands.md)：如果缺少 CLI 或 `nullclaw --help` 尚無法執行，請先返回本頁完成安裝
- [開發指南](./development.md)：若貢獻者工作流程需要乾淨的本地執行檔設定，可返回本頁參閱

## 前置需求

- 若要從原始碼編譯，必須使用 **Zig 0.16.0**。Debian 設定步驟請參閱 [Zig 安裝指南](./zig-installation.md)。
- Git（原始碼安裝所需）。

檢查 Zig 版本：

```bash
zig version
```

輸出結果必須為 `0.16.0`。

## 方式 1：Homebrew（推薦 macOS/Linux 使用）

```bash
brew install nullclaw
nullclaw --help
```

若指令可正常執行並顯示說明，表示安裝完成。

## 方式 2：官方容器映像檔（Docker / Podman）

NullClaw 在 `ghcr.io/nullclaw/nullclaw` 提供官方 OCI 容器映像檔。

容器將其持久化狀態統一存儲於 `/nullclaw-data`：

- 設定檔：`/nullclaw-data/config.json`
- 工作區（Workspace）：`/nullclaw-data/workspace`

內建的入門設定已經採用目前的結構配置（`agents.defaults.model.primary` 加上 `models.providers`），因此在自訂 Provider 憑證之前，`latest` 映像檔應能正常開機啟動。

### 快速執行單次指令

```bash
docker run --rm -it \
  -v nullclaw-data:/nullclaw-data \
  ghcr.io/nullclaw/nullclaw:latest status
```

互動式初始化設定：

```bash
docker run --rm -it \
  -v nullclaw-data:/nullclaw-data \
  ghcr.io/nullclaw/nullclaw:latest onboard --interactive
```

執行互動式 Agent：

```bash
docker run --rm -it \
  -v nullclaw-data:/nullclaw-data \
  ghcr.io/nullclaw/nullclaw:latest agent
```

啟動 HTTP 閘道（Gateway）：

```bash
docker run --rm -it \
  -p 127.0.0.1:3000:3000 \
  -v nullclaw-data:/nullclaw-data \
  ghcr.io/nullclaw/nullclaw:latest
```

### Docker Compose

專案儲存庫內建了 `docker-compose.yml`，預設使用官方映像檔。

互動式引導設定（Onboard）：

```bash
docker compose --profile agent run --rm agent onboard --interactive
```

在官方容器流程中，於工作區提示處直接按下 Enter，將保留磁碟區支援的預設路徑：

- 工作區：`/nullclaw-data/workspace`

啟動互動式 Agent 連線階段：

```bash
docker compose --profile agent run --rm agent
```

啟動常駐 HTTP 閘道服務：

```bash
docker compose --profile gateway up -d gateway
```

Profile 設定說明：

- `agent`：一次性的互動式 CLI 容器
- `gateway`：常駐的 HTTP 閘道，發布在主機 loopback 連接埠 `3000`

若您需要開放區域網路（LAN）或公開對外連線，請謹慎變更綁定的主機 IP，並請先檢閱 [安全機制](./security.md)。

若之後要釘選特定釋出標籤或切換映像檔登錄庫，可覆寫 `NULLCLAW_IMAGE` 環境變數：

```bash
NULLCLAW_IMAGE=ghcr.io/nullclaw/nullclaw:v2026.3.11 docker compose --profile gateway up -d gateway
```

## 方式 3：從原始碼建置（跨平台）

```bash
git clone https://github.com/nullclaw/nullclaw.git
cd nullclaw
zig build -Doptimize=ReleaseSmall
zig build test --summary all
```

建置產出檔案：

- `zig-out/bin/nullclaw`

## 方式 4：Android / Termux

Android / Termux 共有三種不同的安裝途徑：

- 從 GitHub Releases 下載官方預先建置的 Android / Termux 二進位執行檔
- 直接在 Android 裝置上的 Termux 環境內建置
- 從其他電腦為 Android 交叉編譯二進位執行檔

### Termux 原生建置

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

- 必須使用精確的 **Zig 0.16.0** 版本。
- 若 `zig build` 立即失敗，請先檢查 Zig 版本。
- 此方式使用當前 Termux 環境的原生目標架構，因此通常**不需要**指定 `-Dtarget`。
- 在 Android / Termux 上，建議先以前景模式執行（`agent`、`gateway`），再嘗試將其作為背景服務管理。
- 官方 Releases 會發行適用於 `aarch64`、`armv7` 與 `x86_64` 架構的預先建置 Android / Termux 執行檔。
- 關於更完整的 Android / Termux 安裝與疑難排解指南，請參閱 [Termux 指南](./termux.md)。

### 為 Android 進行交叉編譯

若您在其他電腦上為 Termux / Android 裝置建置，請傳入明確的 Zig target 與 Android libc/sysroot 檔案。僅指定 `-Dtarget` 是不夠的：

```bash
zig build -Dtarget=aarch64-linux-android.24 -Doptimize=ReleaseSmall --libc /path/to/android-libc-aarch64.txt
```

常見的 Android 目標架構：

- `aarch64-linux-android.24`
- `arm-linux-androideabi.24` 搭配 `-Dcpu=baseline+v7a`
- `x86_64-linux-android.24`

請使用與手機或模擬器硬體架構相符的目標。
從 Android NDK 產生 `--libc` 檔案的完整範例請參閱 [`.github/workflows/release.yml`](../../.github/workflows/release.yml)。
官方 Releases 也會附上針對 Android API 24 建置的相應 Android / Termux 執行檔。

## 將二進位執行檔加入 PATH

### 自行編譯的執行檔

#### macOS/Linux（zsh/bash）

```bash
zig build -Doptimize=ReleaseSmall -p "$HOME/.local"
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.zshrc
# bash 使用者請使用 ~/.bashrc
source ~/.zshrc
```

#### Windows（PowerShell）

```powershell
zig build -Doptimize=ReleaseSmall -p "$HOME\.local"

$bin = "$HOME\.local\bin"
$user_path = [Environment]::GetEnvironmentVariable("Path", "User")
if (-not ($user_path -split ";" | Where-Object { $_ -eq $bin })) {
  [Environment]::SetEnvironmentVariable("Path", "$user_path;$bin", "User")
}
$env:Path = "$env:Path;$bin"
```

### 下載的 nullclaw 執行檔（Windows PowerShell）

從 Releases 頁面下載 Windows `.zip` 壓縮檔並解壓縮後，以系統管理員權限在 PowerShell 中執行以下指令，將包含 `nullclaw.exe` 的目錄新增至 Windows 的 `PATH` 環境變數：

```powershell
$old = [Environment]::GetEnvironmentVariable("Path", "Machine")
$new = "$old;x:\path\to\nullclaw"
[Environment]::SetEnvironmentVariable("Path", $new, "Machine")
```

## 驗證安裝

```bash
nullclaw --help
nullclaw --version
nullclaw status
```

若 `status` 成功回傳各元件狀態，表示執行環境基礎設定已就緒。

## 升級與解除安裝

### Homebrew（推薦 macOS/Linux 使用）

- 升級：
```bash
brew update
brew upgrade nullclaw
```
- 解除安裝：
```bash
brew uninstall nullclaw
```

### 命令提示字元（CMD）（Windows）

- 升級：`nullclaw update`
- 解除安裝：刪除 `nullclaw` 執行檔，並從環境變數 PATH 中移除包含該執行檔的目錄（若有設定）。

### 原始碼安裝

- 升級：`git pull`，然後使用 `zig build -Doptimize=ReleaseSmall` 重新編譯。
- 解除安裝：刪除已安裝的 `nullclaw` 執行檔，並從 PATH 中移除相關設定。

## 下一步

- 執行 `nullclaw onboard --interactive`，然後閱讀 [設定指南](./configuration.md)
- 參閱 [使用與維運](./usage.md) 了解首次執行指令、服務模式與疑難排解
- 安裝後若需要以任務為導向的 CLI 指令清單，請查閱 [指令參考](./commands.md)

## 相關頁面

- [首頁](./README.md)
- [Termux 指南](./termux.md)
- [設定指南](./configuration.md)
- [使用與維運](./usage.md)
- [指令參考](./commands.md)
