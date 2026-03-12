# Installation

This guide covers the main installation paths for macOS, Linux, and Windows.

## Page Guide

**Who this page is for**

- First-time users installing NullClaw on a local machine
- Operators choosing between package install and source build
- Contributors validating the baseline runtime before deeper setup

**Read this next**

- Open [Configuration](./configuration.md) after the binary is installed and on your `PATH`
- Open [Usage and Operations](./usage.md) when you are ready to run first commands and service mode
- Open [README](./README.md) if you want the broader English docs map before going deeper

**If you came from ...**

- [README](./README.md): this page is the concrete first-run path after choosing the installation track
- [Commands](./commands.md): come here first if the CLI is missing or `nullclaw --help` does not work yet
- [Development](./development.md): return here if a contributor workflow also needs a clean local binary setup

## Prerequisites

- If building from source, use **Zig 0.15.2**.
- Git (required for source install).

Check Zig version:

```bash
zig version
```

The output must be `0.15.2`.

## Option 1: Homebrew (recommended for macOS/Linux)

```bash
brew install nullclaw
nullclaw --help
```

If the command works, installation is complete.

## Option 2: Build from Source (cross-platform)

```bash
git clone https://github.com/nullclaw/nullclaw.git
cd nullclaw
zig build -Doptimize=ReleaseSmall
zig build test --summary all
```

Build output:

- `zig-out/bin/nullclaw`

## Option 3: Android / Termux

There are three different paths:

- download an official pre-built Android / Termux binary from releases
- build directly inside Termux on the Android device
- cross-compile an Android binary from another machine

### Termux native build

```bash
pkg update
pkg install git zig
git clone https://github.com/nullclaw/nullclaw.git
cd nullclaw
zig version
zig build -Doptimize=ReleaseSmall
./zig-out/bin/nullclaw --help
```

Notes:

- Use **Zig 0.15.2** exactly.
- If `zig build` fails immediately, verify the Zig version first.
- This uses the native target of the current Termux environment, so you usually do **not** need `-Dtarget`.
- On Android / Termux, prefer foreground use first (`agent`, `gateway`) before trying to manage it as a background service.
- Official releases publish pre-built Android / Termux binaries for `aarch64`, `armv7`, and `x86_64`.

### Cross-compiling for Android

If you are building on another machine for a Termux / Android device, pass an explicit Zig target:

```bash
zig build -Dtarget=aarch64-linux-android.24 -Doptimize=ReleaseSmall
```

Common Android targets:

- `aarch64-linux-android.24`
- `arm-linux-androideabi.24` with `-Dcpu=baseline+v7a`
- `x86_64-linux-android.24`

Use the target that matches the phone or emulator architecture.
Official releases also attach matching Android / Termux binaries built for Android API 24.

## Add Binary to PATH

### macOS/Linux (zsh/bash)

```bash
zig build -Doptimize=ReleaseSmall -p "$HOME/.local"
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.zshrc
# bash users: use ~/.bashrc
source ~/.zshrc
```

### Windows (PowerShell)

```powershell
zig build -Doptimize=ReleaseSmall -p "$HOME\.local"

$bin = "$HOME\.local\bin"
$user_path = [Environment]::GetEnvironmentVariable("Path", "User")
if (-not ($user_path -split ";" | Where-Object { $_ -eq $bin })) {
  [Environment]::SetEnvironmentVariable("Path", "$user_path;$bin", "User")
}
$env:Path = "$env:Path;$bin"
```

## Verify Installation

```bash
nullclaw --help
nullclaw --version
nullclaw status
```

If `status` returns component state successfully, runtime basics are ready.

## Upgrade and Uninstall

### Homebrew

```bash
brew update
brew upgrade nullclaw
brew uninstall nullclaw
```

### Source install

- Upgrade: `git pull`, then rebuild with `zig build -Doptimize=ReleaseSmall`.
- Uninstall: delete the installed `nullclaw` binary and remove the PATH entry.

## Next Steps

- Run `nullclaw onboard --interactive`, then continue with [Configuration](./configuration.md)
- Use [Usage and Operations](./usage.md) for first-run commands, service mode, and troubleshooting
- Keep [Commands](./commands.md) nearby if you want a task-based CLI reference after install

## Related Pages

- [README](./README.md)
- [Configuration](./configuration.md)
- [Usage and Operations](./usage.md)
- [Commands](./commands.md)
