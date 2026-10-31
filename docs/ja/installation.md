# インストール

このガイドでは、macOS、Linux、Windows における主なインストール方法を説明します。

## ページガイド

**このページの対象読者**

- ローカルマシンに初めて NullClaw をインストールするユーザー
- パッケージインストール、コンテナデプロイ、ソースビルドのいずれかを選ぶ運用担当者
- 本格的なセットアップの前に、ベースとなるランタイムを検証するコントリビューター

**次に読むページ**

- バイナリをインストールして `PATH` に追加したら、[設定](./configuration.md) を開いてください
- 最初のコマンドやサービスモードを実行する準備ができたら、[使い方と運用](./usage.md) を開いてください
- 詳しく読み進める前にドキュメントの全体像を把握したい場合は、[README](./README.md) を開いてください

**以下のページから来た場合**

- [README](./README.md): このページは、インストール方法を選んだ後の具体的な初回実行の手順です
- [コマンド](./commands.md): CLI が見つからない場合や `nullclaw --help` がまだ動作しない場合は、まずこのページに来てください
- [開発](./development.md): コントリビューターのワークフローでクリーンなローカルバイナリのセットアップも必要な場合は、このページに戻ってきてください

## 前提条件

- ソースからビルドする場合は **Zig 0.16.0** を使用してください。Debian でのセットアップについては [Zig のインストール](./zig-installation.md) を参照してください。
- Git（ソースからのインストールに必要です）。

Zig のバージョンを確認します:

```bash
zig version
```

出力は `0.16.0` である必要があります。

## オプション 1: Homebrew（macOS/Linux に推奨）

```bash
brew install nullclaw
nullclaw --help
```

コマンドが動作すれば、インストールは完了です。

## オプション 2: 公式コンテナイメージ（Docker / Podman）

NullClaw は公式の OCI イメージを `ghcr.io/nullclaw/nullclaw` で公開しています。

コンテナは永続的な状態を `/nullclaw-data` 配下に保存します:

- 設定: `/nullclaw-data/config.json`
- ワークスペース: `/nullclaw-data/workspace`

同梱のスターター設定はすでに現在のスキーマ（`agents.defaults.model.primary` と `models.providers`）を使用しているため、プロバイダーの認証情報をカスタマイズする前でも `latest` は問題なく起動するはずです。

### 単発のコマンドをすばやく実行する

```bash
docker run --rm -it \
  -v nullclaw-data:/nullclaw-data \
  ghcr.io/nullclaw/nullclaw:latest status
```

対話形式で設定を初期化します:

```bash
docker run --rm -it \
  -v nullclaw-data:/nullclaw-data \
  ghcr.io/nullclaw/nullclaw:latest onboard --interactive
```

対話型エージェントを実行します:

```bash
docker run --rm -it \
  -v nullclaw-data:/nullclaw-data \
  ghcr.io/nullclaw/nullclaw:latest agent
```

HTTP ゲートウェイを実行します:

```bash
docker run --rm -it \
  -p 127.0.0.1:3000:3000 \
  -v nullclaw-data:/nullclaw-data \
  ghcr.io/nullclaw/nullclaw:latest
```

### Docker Compose

リポジトリには、デフォルトで公式イメージを使用する `docker-compose.yml` が同梱されています。

対話型のオンボーディング:

```bash
docker compose --profile agent run --rm agent onboard --interactive
```

公式コンテナのフローでは、ワークスペースのプロンプトで Enter を押すと、ボリュームを使ったデフォルト値がそのまま使われます:

- ワークスペース: `/nullclaw-data/workspace`

対話型のエージェントセッション:

```bash
docker compose --profile agent run --rm agent
```

常駐するゲートウェイ:

```bash
docker compose --profile gateway up -d gateway
```

プロファイルの動作:

- `agent`: 単発の対話型 CLI コンテナ
- `gateway`: ホストのループバックポート `3000` で公開される常駐 HTTP ゲートウェイ

LAN やパブリックへの公開が必要な場合は、公開するホスト IP を意図的に変更し、事前に [セキュリティ](./security.md) を確認してください。

後でリリースタグを固定したりレジストリを切り替えたりするには、`NULLCLAW_IMAGE` を上書きします:

```bash
NULLCLAW_IMAGE=ghcr.io/nullclaw/nullclaw:v2026.3.11 docker compose --profile gateway up -d gateway
```

## オプション 3: ソースからビルド（クロスプラットフォーム）

```bash
git clone https://github.com/nullclaw/nullclaw.git
cd nullclaw
zig build -Doptimize=ReleaseSmall
zig build test --summary all
```

ビルドの出力先:

- `zig-out/bin/nullclaw`

## オプション 4: Android / Termux

Android / Termux には 3 つの方法があります:

- リリースから公式のビルド済み Android / Termux バイナリをダウンロードする
- Android デバイス上の Termux 内で直接ビルドする
- 別のマシンから Android 用バイナリをクロスコンパイルする

### Termux でのネイティブビルド

```bash
pkg update
pkg install git zig
git clone https://github.com/nullclaw/nullclaw.git
cd nullclaw
zig version
zig build -Doptimize=ReleaseSmall
./zig-out/bin/nullclaw --help
```

注意事項:

- Zig は必ず **Zig 0.16.0** を使用してください。
- `zig build` がすぐに失敗する場合は、まず Zig のバージョンを確認してください。
- この方法では現在の Termux 環境のネイティブターゲットを使用するため、通常 `-Dtarget` は**不要**です。
- Android / Termux では、バックグラウンドサービスとして管理しようとする前に、まずフォアグラウンドでの利用（`agent`、`gateway`）を優先してください。
- 公式リリースでは、`aarch64`、`armv7`、`x86_64` 向けのビルド済み Android / Termux バイナリを公開しています。
- トラブルシューティングを含む Android / Termux の詳しい手順については、[Termux ガイド](./termux.md) を参照してください。

### Android 向けのクロスコンパイル

Termux / Android デバイス向けに別のマシンでビルドする場合は、Zig のターゲットと Android の libc/sysroot ファイルを明示的に指定してください。`-Dtarget` だけでは不十分です:

```bash
zig build -Dtarget=aarch64-linux-android.24 -Doptimize=ReleaseSmall --libc /path/to/android-libc-aarch64.txt
```

主な Android ターゲット:

- `aarch64-linux-android.24`
- `arm-linux-androideabi.24`（`-Dcpu=baseline+v7a` と併用）
- `x86_64-linux-android.24`

スマートフォンまたはエミュレーターのアーキテクチャに合ったターゲットを使用してください。
Android NDK から `--libc` ファイルを生成する完全な例については、[`.github/workflows/release.yml`](../../.github/workflows/release.yml) を参照してください。
公式リリースには、Android API 24 向けにビルドされた対応する Android / Termux バイナリも添付されています。

## バイナリを PATH に追加する

### コンパイルしたバイナリファイル

#### macOS/Linux（zsh/bash）

```bash
zig build -Doptimize=ReleaseSmall -p "$HOME/.local"
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.zshrc
# bash users: use ~/.bashrc
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

### ダウンロードした nullclaw バイナリファイル（Windows、Powershell）
リリースページから Windows 用の `.zip` アーカイブをダウンロードして展開し、Powershell で管理者権限を使って以下のコマンドを実行して、`nullclaw.exe` を含むディレクトリを Windows の `PATH` 環境変数に追加します:

```Powershell 
$old = [Environment]::GetEnvironmentVariable("Path", "Machine")
$new = "$old;x:\path\to\nullclaw"
[Environment]::SetEnvironmentVariable("Path", $new, "Machine")
```

## インストールの確認

```bash
nullclaw --help
nullclaw --version
nullclaw status
```

`status` がコンポーネントの状態を正常に返せば、ランタイムの基本的な準備は完了です。

## アップグレードとアンインストール

### Homebrew（macOS/Linux に推奨）

- アップデート:
```bash
brew update
brew upgrade nullclaw
```
- アンインストール:
```bash
brew uninstall nullclaw
```
#### コマンドライン（CMD）（Windows）

- アップデート: `nullclaw update`

- アンインストール: `nullclaw` バイナリファイルを削除し、そのバイナリファイルを含むディレクトリのエントリが環境変数 PATH にあれば削除します。

### ソースからのインストール

- アップグレード: `git pull` を実行してから、`zig build -Doptimize=ReleaseSmall` で再ビルドします。
- アンインストール: インストールした `nullclaw` バイナリを削除し、PATH のエントリを削除します。

## 次のステップ

- `nullclaw onboard --interactive` を実行し、続けて [設定](./configuration.md) に進んでください
- 初回実行のコマンド、サービスモード、トラブルシューティングについては [使い方と運用](./usage.md) を参照してください
- インストール後にタスク別の CLI リファレンスが必要な場合は、[コマンド](./commands.md) を手元に置いておくと便利です

## 関連ページ

- [README](./README.md)
- [Termux ガイド](./termux.md)
- [設定](./configuration.md)
- [使い方と運用](./usage.md)
- [コマンド](./commands.md)
