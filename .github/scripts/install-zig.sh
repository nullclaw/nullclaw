#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 1 ]; then
  echo "usage: $0 <zig-version>" >&2
  exit 1
fi

version="$1"

python_bin="${PYTHON:-python3}"
if ! command -v "$python_bin" >/dev/null 2>&1; then
  python_bin="python"
fi
if ! command -v "$python_bin" >/dev/null 2>&1; then
  echo "python is required to install Zig" >&2
  exit 1
fi

runner_os="${RUNNER_OS:-$(uname -s)}"
runner_arch="${RUNNER_ARCH:-$(uname -m)}"

case "$runner_os" in
  Linux | linux)
    zig_os="linux"
    ;;
  Darwin | macOS)
    zig_os="macos"
    ;;
  Windows | MINGW* | MSYS* | CYGWIN*)
    zig_os="windows"
    ;;
  *)
    echo "unsupported runner OS: $runner_os" >&2
    exit 1
    ;;
esac

case "$runner_arch" in
  X64 | x86_64 | amd64)
    zig_arch="x86_64"
    ;;
  ARM64 | arm64 | aarch64)
    zig_arch="aarch64"
    ;;
  *)
    echo "unsupported runner architecture: $runner_arch" >&2
    exit 1
    ;;
esac

host_key="${zig_arch}-${zig_os}"
tool_root="${RUNNER_TEMP:-${TMPDIR:-/tmp}}/nullclaw-zig"
install_dir="${tool_root}/${version}/${host_key}"
zig_bin="zig"
if [ "$zig_os" = "windows" ]; then
  zig_bin="zig.exe"
fi

if [ ! -x "${install_dir}/${zig_bin}" ]; then
  mkdir -p "$(dirname "$install_dir")"

  zig_metadata="$(
    "$python_bin" - "$version" "$host_key" <<'PY'
import json
import sys
import urllib.request

version = sys.argv[1]
host_key = sys.argv[2]

with urllib.request.urlopen("https://ziglang.org/download/index.json") as response:
    data = json.load(response)

host = data.get(version, {}).get(host_key)
if not host:
    raise SystemExit(f"missing Zig download metadata for version={version!r} host={host_key!r}")

archive_url = host.get("tarball") or host.get("zip")
checksum = host.get("shasum") or ""
if not archive_url:
    raise SystemExit(f"missing archive URL for version={version!r} host={host_key!r}")

print(archive_url)
print(checksum)
PY
  )"

  archive_url="$(printf '%s\n' "$zig_metadata" | sed -n '1p')"
  expected_sha="$(printf '%s\n' "$zig_metadata" | sed -n '2p')"
  if [ -z "$archive_url" ]; then
    echo "failed to resolve Zig download URL" >&2
    exit 1
  fi

  archive_name="${archive_url##*/}"
  archive_dir="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/zig-archive.XXXXXX")"
  archive_path="${archive_dir}/${archive_name}"
  extract_dir="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/zig-extract.XXXXXX")"
  trap 'rm -rf "$archive_dir"; rm -rf "$extract_dir"' EXIT

  curl -fsSL --retry 3 --retry-all-errors "$archive_url" -o "$archive_path"

  "$python_bin" - "$archive_path" "$expected_sha" <<'PY'
import hashlib
import sys

path = sys.argv[1]
expected = sys.argv[2].strip().lower()
if not expected:
    raise SystemExit(0)

digest = hashlib.sha256()
with open(path, "rb") as handle:
    for chunk in iter(lambda: handle.read(1024 * 1024), b""):
        digest.update(chunk)

actual = digest.hexdigest().lower()
if actual != expected:
    raise SystemExit(f"checksum mismatch for {path}: expected {expected}, got {actual}")
PY

  "$python_bin" - "$archive_path" "$extract_dir" <<'PY'
import pathlib
import sys
import tarfile
import zipfile

archive = pathlib.Path(sys.argv[1])
destination = pathlib.Path(sys.argv[2])
destination.mkdir(parents=True, exist_ok=True)

def ensure_within_destination(relative_name: str) -> None:
    target = (destination / relative_name).resolve()
    if destination.resolve() not in target.parents and target != destination.resolve():
        raise SystemExit(f"archive entry escapes destination: {relative_name}")

if archive.suffix == ".zip":
    with zipfile.ZipFile(archive) as handle:
        for member in handle.namelist():
            ensure_within_destination(member)
        handle.extractall(destination)
else:
    with tarfile.open(archive, "r:*") as handle:
        for member in handle.getnames():
            ensure_within_destination(member)
        handle.extractall(destination)
PY

  extracted_dir="$(find "$extract_dir" -mindepth 1 -maxdepth 1 -type d | head -n 1)"
  if [ -z "$extracted_dir" ]; then
    echo "failed to extract Zig archive: $archive_url" >&2
    exit 1
  fi

  rm -rf "$install_dir"
  mv "$extracted_dir" "$install_dir"
fi

if [ -n "${GITHUB_PATH:-}" ]; then
  printf '%s\n' "$install_dir" >> "$GITHUB_PATH"
else
  echo "GITHUB_PATH is not set; add this directory to PATH manually: $install_dir" >&2
fi

"${install_dir}/${zig_bin}" version
