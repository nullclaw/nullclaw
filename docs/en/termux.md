# Termux Guide

This guide covers the practical Android / Termux path for NullClaw.

## Page Guide

**Who this page is for**

- Android users running NullClaw directly inside Termux
- Contributors documenting or troubleshooting mobile installs
- Operators deciding whether Termux is good enough for their workload

**Read this next**

- Open [Installation](./installation.md) if you want the broader install matrix first
- Open [Configuration](./configuration.md) after the binary runs
- Open [Usage and Operations](./usage.md) when you are ready to test `agent` or `gateway`

## What to Expect

Termux works best for:

- foreground use
- manual testing
- constrained local deployments

Termux is a weaker fit for:

- long-running heavy inference on the phone itself
- service-style background operation that must survive Android process pressure

If Android kills the process under memory pressure, that is an Android / Termux constraint, not necessarily a NullClaw bug.

## Prerequisites

- **Zig 0.15.2 exactly**
- Git
- enough local storage for the repository and build cache

Verify Zig before building:

```bash
zig version
```

The output must be `0.15.2`.

## Native Termux Build

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

- In native Termux builds you usually do **not** need `-Dtarget`.
- Prefer `-Doptimize=ReleaseSmall` or `-Doptimize=ReleaseFast`.
- Do **not** use the older `-Drelease-fast` syntax from old examples.

## Lower-Dependency Build

If SQLite fetch or build steps fail in Termux, try the lighter engine set first:

```bash
zig build -Doptimize=ReleaseSmall -Dengines=base
```

`-Dengines=base` keeps `markdown,memory,api,none` and avoids SQLite.

You can also pick explicit engines:

```bash
zig build -Doptimize=ReleaseSmall -Dengines=markdown,memory
```

This is often the best first milestone on smaller Android devices.

## Common Failure: `build.zig.zon` "expected string literal"

If you see an error like:

```text
build.zig.zon:2:14: error: expected string literal
```

the usual cause is the wrong Zig version, not the NullClaw source tree.

Checklist:

1. Run `zig version`.
2. Confirm it prints `0.15.2`.
3. If it does not, replace the Zig package/binary before trying again.

Do not patch `build.zig.zon` locally to work around an older Zig build. The project is pinned to Zig 0.15.2.

## First Runtime Check

Once the binary builds, verify the two simplest entry points first:

```bash
./zig-out/bin/nullclaw agent
./zig-out/bin/nullclaw gateway --host 127.0.0.1 --port 3001
```

Start with foreground runs before trying wrappers, launchers, or background automation.

## Cross-Compiling for Android

If you are building on another machine for a Termux / Android device, you need both the Zig target and an Android libc/sysroot file:

```bash
zig build -Dtarget=aarch64-linux-android.24 -Doptimize=ReleaseSmall --libc /path/to/android-libc-aarch64.txt
```

Common targets:

- `aarch64-linux-android.24`
- `arm-linux-androideabi.24` with `-Dcpu=baseline+v7a`
- `x86_64-linux-android.24`

Use the target that matches the device architecture.
For a complete example of generating the `--libc` file from the Android NDK, see [`.github/workflows/release.yml`](../../.github/workflows/release.yml).

## Practical Advice

- Keep the first goal small: build the binary, run `--help`, then run `agent` or `gateway`.
- If the device is RAM-constrained, prefer remote model providers first.
- If you need stable long-running workloads, Termux may be a testbed rather than the final host.

## Related Pages

- [Installation](./installation.md)
- [Configuration](./configuration.md)
- [Usage and Operations](./usage.md)
- [Commands](./commands.md)
