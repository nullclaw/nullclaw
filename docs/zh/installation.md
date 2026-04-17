# 安装指南

本指南覆盖 macOS、Linux、Windows 的主流安装方式。

## 页面导航

- 这页适合谁：刚准备安装 NullClaw，或者要确认本机环境、容器部署、升级与卸载路径的人。
- 看完去哪里：安装完成后先看 [配置指南](./configuration.md)；想直接跑一遍常用命令看 [使用与运维](./usage.md)；想先浏览 CLI 入口看 [命令参考](./commands.md)。
- 如果你是从某页来的：从 [README](./README.md) 来，这页就是落地安装的第一站；从 [命令参考](./commands.md) 来，适合回头补齐本机安装与 PATH；从 [开发指南](./development.md) 来，可把本页当作本地环境准备清单。

## 前置要求

- 如果走源码构建：必须使用 **Zig 0.16.0**。
- Git（源码安装需要）。

检查 Zig 版本：

```bash
zig version
```

输出必须是 `0.16.0`。

## 方式一：使用二进制文件
### Homebrew（macOS/Linux推荐）

```bash
brew install nullclaw
nullclaw --help
```
如果命令可用，说明安装成功。

### 命令行（CMD）(Windows)

从发布页下载 Windows `.zip` 压缩包并解压后，即可直接在命令行中运行其中的 `nullclaw.exe`。

比如检查nullclaw版本号的命令如下：

```cmd
x:\path\nullclaw.exe --version
```

## 方式二：官方容器镜像（Docker / Podman）

NullClaw 当前提供官方 OCI 镜像：`ghcr.io/nullclaw/nullclaw`。

容器内的持久化目录统一放在 `/nullclaw-data`：

- 配置文件：`/nullclaw-data/config.json`
- 工作区：`/nullclaw-data/workspace`

镜像内自带的初始配置已经使用当前配置结构（`agents.defaults.model.primary` 和 `models.providers`），因此在你填入 provider 凭证之前，`latest` 也应能正常启动。

### 单次命令

```bash
docker run --rm -it \
  -v nullclaw-data:/nullclaw-data \
  ghcr.io/nullclaw/nullclaw:latest status
```

交互式初始化配置：

```bash
docker run --rm -it \
  -v nullclaw-data:/nullclaw-data \
  ghcr.io/nullclaw/nullclaw:latest onboard --interactive
```

运行交互式 agent：

```bash
docker run --rm -it \
  -v nullclaw-data:/nullclaw-data \
  ghcr.io/nullclaw/nullclaw:latest agent
```

运行 HTTP gateway：

```bash
docker run --rm -it \
  -p 127.0.0.1:3000:3000 \
  -v nullclaw-data:/nullclaw-data \
  ghcr.io/nullclaw/nullclaw:latest
```

### Docker Compose

仓库根目录自带 `docker-compose.yml`，默认直接使用官方镜像。

交互式初始化：

```bash
docker compose --profile agent run --rm agent onboard --interactive
```

在官方容器流程里，workspace 提示直接回车即可保留挂载卷里的默认路径：

- 工作区：`/nullclaw-data/workspace`

交互式 agent 会话：

```bash
docker compose --profile agent run --rm agent
```

长期运行 gateway：

```bash
docker compose --profile gateway up -d gateway
```

Profile 含义：

- `agent`：一次性的交互式 CLI 容器
- `gateway`：长期运行的 HTTP gateway，默认发布到宿主机回环地址 `3000`

如果你需要局域网或公网访问，请显式修改发布地址，并先阅读 [安全指南](./security.md)。

如果你要固定版本标签，或者以后切换到其他镜像仓库，可以覆盖 `NULLCLAW_IMAGE`：

```bash
NULLCLAW_IMAGE=ghcr.io/nullclaw/nullclaw:v2026.3.11 docker compose --profile gateway up -d gateway
```

## 方式三：源码构建（通用）

```bash
git clone https://github.com/nullclaw/nullclaw.git
cd nullclaw
zig build -Doptimize=ReleaseSmall
zig build test --summary all
```

构建产物：

- `zig-out/bin/nullclaw`

## 方式四：Android / Termux

有三种常见路径：

- 直接下载官方发布的 Android / Termux 预构建二进制
- 在手机上的 Termux 里原生构建
- 在另一台机器上交叉编译 Android 二进制

### Termux 原生构建

```bash
pkg update
pkg install git zig
git clone https://github.com/nullclaw/nullclaw.git
cd nullclaw
zig version
zig build -Doptimize=ReleaseSmall
./zig-out/bin/nullclaw --help
```

说明：

- 必须使用 **Zig 0.16.0**
- 如果 `zig build` 一开始就失败，先确认 Zig 版本
- Termux 原生构建使用当前环境的 native target，通常不需要手动传 `-Dtarget`
- 在 Android / Termux 上，建议先跑前台命令（如 `agent`、`gateway`），确认没问题后再考虑后台托管
- 官方 release 提供 `aarch64`、`armv7`、`x86_64` 的 Android / Termux 预构建二进制
- 更完整的说明和排错见 [Termux 指南](./termux.md)。

### 为 Android 交叉编译

如果你是在另一台机器上给 Android / Termux 设备构建，需要显式传入 Zig target，并提供 Android 的 libc/sysroot 文件；只传 `-Dtarget` 还不够：

```bash
zig build -Dtarget=aarch64-linux-android.24 -Doptimize=ReleaseSmall --libc /path/to/android-libc-aarch64.txt
```

常见 Android targets：

- `aarch64-linux-android.24`
- `arm-linux-androideabi.24`，配合 `-Dcpu=baseline+v7a`
- `x86_64-linux-android.24`

选择与目标手机或模拟器架构匹配的 target。完整的 `--libc` 文件生成示例可参考 [`.github/workflows/release.yml`](../../.github/workflows/release.yml)。官方 release 也附带基于 Android API 24 构建的对应二进制。

## 将二进制加入 PATH

### 使用编译后的二进制文件

#### macOS/Linux（zsh/bash）

```bash
zig build -Doptimize=ReleaseSmall -p "$HOME/.local"
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.zshrc
# bash 用户改为 ~/.bashrc
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

### 直接使用下载的二进制文件（Windows, Powershell)
从发布页下载 Windows `.zip` 压缩包并解压后，可在管理员权限的 Powershell 中执行如下命令，将 `nullclaw.exe` 所在目录加入 Windows 的 `PATH` 环境变量：

```Powershell 
$old = [Environment]::GetEnvironmentVariable("Path", "Machine")
$new = "$old;x:\path\to\nullclaw"
[Environment]::SetEnvironmentVariable("Path", $new, "Machine")
```

## 安装验证

```bash
nullclaw --help
nullclaw --version
nullclaw status
```

若 `status` 能正常输出组件状态，说明安装与运行环境基本可用。

## 升级与卸载

### 使用二进制文件

#### Homebrew（macOS/Linux推荐）

```bash
brew update
brew upgrade nullclaw
brew uninstall nullclaw
```
#### 命令行（CMD)（Windows）

- 升级： `nullclaw update`
- 卸载：直接删除nullclaw二进制文件。
检查系统变量PATH，若存在就将nullclaw二进制文件的所在目录从中删除。

### 源码安装

- 升级：`git pull` 后重新执行 `zig build -Doptimize=ReleaseSmall`
- 卸载：删除安装位置中的 `nullclaw` 二进制，并移除 PATH 配置行

## 下一步

- 要开始初始化配置：继续看 [配置指南](./configuration.md)，先生成可运行的 `config.json`。
- 要快速跑通一遍：继续看 [使用与运维](./usage.md)，按首次启动流程验证安装结果。
- 要核对 CLI 命令：继续看 [命令参考](./commands.md)，确认 `onboard`、`agent`、`gateway` 等入口。

## 相关页面

- [中文文档入口](./README.md)
- [Termux 指南](./termux.md)
- [配置指南](./configuration.md)
- [使用与运维](./usage.md)
- [命令参考](./commands.md)
