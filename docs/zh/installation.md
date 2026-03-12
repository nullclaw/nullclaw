# 安装指南

本指南覆盖 macOS、Linux、Windows 的主流安装方式。

## 页面导航

- 这页适合谁：刚准备安装 NullClaw，或者要确认本机环境、升级与卸载路径的人。
- 看完去哪里：安装完成后先看 [配置指南](./configuration.md)；想直接跑一遍常用命令看 [使用与运维](./usage.md)；想先浏览 CLI 入口看 [命令参考](./commands.md)。
- 如果你是从某页来的：从 [README](./README.md) 来，这页就是落地安装的第一站；从 [命令参考](./commands.md) 来，适合回头补齐本机安装与 PATH；从 [开发指南](./development.md) 来，可把本页当作本地环境准备清单。

## 前置要求

- 如果走源码构建：必须使用 **Zig 0.15.2**。
- Git（源码安装需要）。

检查 Zig 版本：

```bash
zig version
```

输出必须是 `0.15.2`。

## 方式一：Homebrew（推荐，macOS/Linux）

```bash
brew install nullclaw
nullclaw --help
```

如果命令可用，说明安装成功。

## 方式二：源码构建（通用）

```bash
git clone https://github.com/nullclaw/nullclaw.git
cd nullclaw
zig build -Doptimize=ReleaseSmall
zig build test --summary all
```

构建产物：

- `zig-out/bin/nullclaw`

## 将二进制加入 PATH

### macOS/Linux（zsh/bash）

```bash
zig build -Doptimize=ReleaseSmall -p "$HOME/.local"
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.zshrc
# bash 用户改为 ~/.bashrc
source ~/.zshrc
```

### Windows（PowerShell）

```powershell
zig build -Doptimize=ReleaseSmall -p "$HOME\.local"

$bin = "$HOME\.local\bin"
$user_path = [Environment]::GetEnvironmentVariable("Path", "User")
if (-not ($user_path -split ";" | Where-Object { $_ -eq $bin })) {
  [Environment]::SetEnvironmentVariable("Path", "$user_path;$bin", "User")
}
$env:Path = "$env:Path;$bin"
```

## 安装验证

```bash
nullclaw --help
nullclaw --version
nullclaw status
```

若 `status` 能正常输出组件状态，说明安装与运行环境基本可用。

## 升级与卸载

### Homebrew

```bash
brew update
brew upgrade nullclaw
brew uninstall nullclaw
```

### 源码安装

- 升级：`git pull` 后重新执行 `zig build -Doptimize=ReleaseSmall`
- 卸载：删除安装位置中的 `nullclaw` 二进制，并移除 PATH 配置行

## 下一步

- 要开始初始化配置：继续看 [配置指南](./configuration.md)，先生成可运行的 `config.json`。
- 要快速跑通一遍：继续看 [使用与运维](./usage.md)，按首次启动流程验证安装结果。
- 要核对 CLI 命令：继续看 [命令参考](./commands.md)，确认 `onboard`、`agent`、`gateway` 等入口。

## 相关页面

- [中文文档入口](./README.md)
- [配置指南](./configuration.md)
- [使用与运维](./usage.md)
- [命令参考](./commands.md)
