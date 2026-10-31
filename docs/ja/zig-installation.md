# Zig のインストール

## 可能な場合はパッケージでのインストールを優先する

macOS または Linux ですでに Homebrew を使用している場合、最も手早い方法は
ビルド済みの NullClaw パッケージです。ローカルの Zig ツールチェーンは不要です:

```bash
brew install nullclaw
```

以下の Debian の手順は、NullClaw をソースからビルドしたい場合で、かつ
固定された Zig 0.16.0 ツールチェーンが厳密に必要な場合にのみ使用してください。

## Debian

以下の手順では、新規の Debian システムに公式の x86_64 Linux 用 tarball から Zig 0.16.0 をインストールします。
`apt` コマンドは root として実行するか、root 以外のユーザーを使っている場合は各コマンドの先頭に `sudo` を付けてください。

リポジトリの CI とコンテナビルドでは、`.github/scripts/install-zig.sh` を通じて Zig のダウンロードを解決しています。
このページでは、最初のソースビルドの前に Zig をセットアップするユーザー向けに、Debian での手動の手順を明示的に残しています。

1. パッケージインデックスを更新します:

   ```bash
   apt update
   ```

2. ダウンロードと展開に使うツールをインストールします:

   ```bash
   apt install -y ca-certificates wget xz-utils
   ```

3. [ziglang.org/download](https://ziglang.org/download/) にアクセスし、
   Zig 0.16.0 の URL をコピーします。一般的な Debian x86_64 マシンでは、Linux の `x86_64`
   版がそれにあたります:

   [https://ziglang.org/download/0.16.0/zig-x86_64-linux-0.16.0.tar.xz](https://ziglang.org/download/0.16.0/zig-x86_64-linux-0.16.0.tar.xz)

4. tarball をダウンロードします:

   ```bash
   wget https://ziglang.org/download/0.16.0/zig-x86_64-linux-0.16.0.tar.xz
   ```

5. 公式のダウンロードメタデータにあるチェックサムでアーカイブを検証します:

   ```bash
   printf '%s  %s\n' \
     70e49664a74374b48b51e6f3fdfbf437f6395d42509050588bd49abe52ba3d00 \
     zig-x86_64-linux-0.16.0.tar.xz | sha256sum -c -
   ```

6. アーカイブを展開します:

   ```bash
   tar -xf zig-x86_64-linux-0.16.0.tar.xz
   ```

7. 展開したディレクトリを `PATH` に追加します:

   ```bash
   export PATH="$PWD/zig-x86_64-linux-0.16.0:$PATH"
   ```

   新しいシェルでも Zig を使えるようにするには、展開したディレクトリの絶対パスを使った
   同じ `export` 行をシェルのプロファイルに追加してください。

8. 必要なバージョンと厳密に一致していることを確認します:

   ```bash
   zig version
   ```

   出力は `0.16.0` でなければなりません。
