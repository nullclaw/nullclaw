# Termux 指南

本页专门讲 Android / Termux 下运行 NullClaw 的实际路径。

## 页面导航

- 这页适合谁：想直接在 Android 手机的 Termux 里构建和运行 NullClaw 的用户。
- 看完去哪里：二进制能跑起来后，继续看 [配置指南](./configuration.md)；准备验证常用命令时看 [使用与运维](./usage.md)。
- 如果你想先看完整安装矩阵：先回到 [安装指南](./installation.md)。

## 先有预期

Termux 更适合：

- 前台使用
- 手动测试
- 轻量本地部署

Termux 不太适合：

- 手机上直接跑高负载、本地推理
- 必须长期稳定常驻后台的服务

如果 Android 因为内存压力杀掉进程，这通常是 Android / Termux 的运行约束，不一定是 NullClaw 自身的 bug。

## 前置要求

- **Zig 0.15.2，必须精确匹配**
- Git
- 足够的本地存储空间

先确认 Zig 版本：

```bash
zig version
```

输出必须是 `0.15.2`。

## 直接在 Termux 里构建

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

- 在原生 Termux 环境里，一般 **不需要** 额外传 `-Dtarget`。
- 优先使用 `-Doptimize=ReleaseSmall` 或 `-Doptimize=ReleaseFast`。
- 不要再用旧示例里的 `-Drelease-fast` 语法。

## 低依赖构建路径

如果 SQLite 的拉取或构建在 Termux 里失败，先走轻量引擎集：

```bash
zig build -Doptimize=ReleaseSmall -Dengines=base
```

`-Dengines=base` 包含 `markdown,memory,api,none`，不依赖 SQLite。

也可以显式指定：

```bash
zig build -Doptimize=ReleaseSmall -Dengines=markdown,memory
```

对内存和依赖都更紧的 Android 设备，这通常是更稳妥的第一步。

## 常见错误：`build.zig.zon` 提示 `expected string literal`

如果你看到类似错误：

```text
build.zig.zon:2:14: error: expected string literal
```

最常见原因是 Zig 版本不对，不是 NullClaw 源码本身有问题。

排查顺序：

1. 运行 `zig version`
2. 确认输出是 `0.15.2`
3. 如果不是，先替换 Zig，再重新构建

不要为了兼容旧 Zig 去本地修改 `build.zig.zon`。项目当前就是固定在 Zig 0.15.2。

## 第一次运行怎么验

编译通过后，先验证最基础的两个入口：

```bash
./zig-out/bin/nullclaw agent
./zig-out/bin/nullclaw gateway --host 127.0.0.1 --port 3001
```

先跑前台，再考虑脚本包装、常驻后台或者别的自动化方式。

## 从别的机器交叉编译 Android 二进制

如果你是在另一台机器上为 Android / Termux 设备构建，除了 Zig target，还需要提供 Android 的 libc/sysroot 文件；只传 `-Dtarget` 还不够：

```bash
zig build -Dtarget=aarch64-linux-android.24 -Doptimize=ReleaseSmall --libc /path/to/android-libc-aarch64.txt
```

常见目标：

- `aarch64-linux-android.24`
- `arm-linux-androideabi.24` 搭配 `-Dcpu=baseline+v7a`
- `x86_64-linux-android.24`

按设备架构选择目标即可。完整的 `--libc` 文件生成示例可参考 [`.github/workflows/release.yml`](../../.github/workflows/release.yml)。

## 实用建议

- 第一阶段目标要小：先成功构建，再跑 `--help`，再跑 `agent` 或 `gateway`。
- 如果设备内存紧张，优先接远程 provider，不要先上本地大模型。
- 如果你需要长期稳定常驻，Termux 更适合作为试验场，而不是最终宿主。

## 相关页面

- [安装指南](./installation.md)
- [配置指南](./configuration.md)
- [使用与运维](./usage.md)
- [命令参考](./commands.md)
