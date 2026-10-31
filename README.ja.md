UI で nullclaw をもっと簡単にインストール・設定したいですか？ [nullhub](https://github.com/nullclaw/nullhub) をお試しください！（現在ベータ版です）

[nullhub](https://github.com/nullclaw/nullhub) は Null エコシステムの UI レイヤーを提供します。nullclaw のセットアップと設定の簡素化、[nullboiler](https://github.com/nullclaw/nullboiler) によるオーケストレーション、[nullwatch](https://github.com/nullclaw/nullwatch) によるオブザーバビリティ、[nulltickets](https://github.com/nullclaw/nulltickets) によるタスク管理を利用できます。

<p align="center">
  <img src="nullclaw.png" alt="nullclaw" width="200" />
</p>

<h1 align="center">NullClaw</h1>

<p align="center">
  <strong>オーバーヘッドはゼロ。妥協もゼロ。100% Zig。100% 非依存。</strong><br>
  <strong>678 KB のバイナリ。RAM は約 1 MB。2 ms 未満で起動。CPU があればどこでも動きます。</strong>
</p>

<p align="center">
  <a href="https://github.com/nullclaw/nullclaw/actions/workflows/ci.yml"><img src="https://github.com/nullclaw/nullclaw/actions/workflows/ci.yml/badge.svg" alt="CI" /></a>
  <a href="https://github.com/nullclaw/nullclaw/actions/workflows/nightly.yml"><img src="https://github.com/nullclaw/nullclaw/actions/workflows/nightly.yml/badge.svg" alt="Nightly" /></a>
  <a href="https://nullclaw.github.io"><img src="https://img.shields.io/badge/docs-nullclaw.github.io-informational" alt="Documentation" /></a>
  <a href="https://discord.gg/Bfmdua22Ud"><img src="https://img.shields.io/badge/discord-join%20community-5865F2?logo=discord&logoColor=white" alt="Discord" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License: MIT" /></a>
</p>

最小の完全自律型 AI アシスタント基盤です。5 ドルのボードにも収まる静的な Zig バイナリで、ミリ秒単位で起動し、libc 以外には何も必要としません。

ドキュメント: [English](docs/en/README.md) · [中文](docs/zh/README.md) · [コントリビュート](CONTRIBUTING.md) · [Discord](https://discord.gg/Bfmdua22Ud)

```
678 KB binary · <2 ms startup · 5,300+ tests · 50+ providers · 19 channels · Pluggable everything
```

### 特徴

- **驚くほど小さい:** 678 KB の静的バイナリです。ランタイムも VM もフレームワークのオーバーヘッドもありません。
- **ほぼゼロのメモリ:** ピーク RSS は約 1 MB です。最も安価な ARM SBC やマイコンでも快適に動作します。
- **即時起動:** Apple Silicon では 2 ms 未満、0.8 GHz のエッジコアでも 8 ms 未満で起動します。
- **真のポータビリティ:** ARM、x86、RISC-V で動く単一の自己完結型バイナリです。どこに置いてもそのまま動きます。
- **機能が完備:** 50 以上のプロバイダー、19 のチャンネル、35 以上のツール、10 のメモリエンジン、多層サンドボックス、トンネル、ハードウェア周辺機器、MCP、サブエージェント、ストリーミング、音声など、フルスタックを備えています。

### nullclaw を選ぶ理由

- **初期状態で軽量:** Zig は小さな静的バイナリにコンパイルされます。アロケーターのオーバーヘッドも、ガベージコレクターも、ランタイムもありません。
- **設計段階からセキュア:** ペアリング、厳格なサンドボックス（landlock、firejail、bubblewrap、docker）、明示的な許可リスト、ワークスペースのスコープ制限、暗号化されたシークレットを備えています。
- **すべて差し替え可能:** コアシステムは vtable インターフェース（プロバイダー、チャンネル、ツール、メモリ、トンネル、周辺機器、オブザーバー、ランタイム）です。
- **ロックインなし:** OpenAI 互換のプロバイダーに対応し、カスタムエンドポイントもプラグインとして追加できます。

## ベンチマークの概要

ローカルマシンでのベンチマーク（macOS arm64、2026 年 2 月）を、0.8 GHz のエッジハードウェア向けに正規化したものです。

| | [OpenClaw](https://github.com/openclaw/openclaw) | [NanoBot](https://github.com/HKUDS/nanobot) | [PicoClaw](https://github.com/sipeed/picoclaw) | [ZeroClaw](https://github.com/zeroclaw-labs/zeroclaw) | **[🦞 NullClaw](https://github.com/nullclaw/nullclaw)** |
|---|---|---|---|---|---|
| **言語** | TypeScript | Python | Go | Rust | **Zig** |
| **RAM** | > 1 GB | > 100 MB | < 10 MB | < 5 MB | **~1 MB** |
| **起動時間（0.8 GHz）** | > 500 s | > 30 s | < 1 s | < 10 ms | **< 8 ms** |
| **バイナリサイズ** | ~28 MB (dist) | N/A（スクリプト） | ~8 MB | ~8.8 MB | **678 KB** |
| **テスト数** | — | — | — | 1,017 | **5,300+** |
| **ソースファイル数** | ~400+ | — | — | ~120 | **~230** |
| **コスト** | Mac Mini $599 | Linux SBC ~$50 | Linux ボード $10 | 任意の $10 ハードウェア | **任意の $5 ハードウェア** |

> ReleaseSmall ビルドで `/usr/bin/time -l` を使って計測しています。nullclaw はランタイム依存関係がゼロの静的バイナリです。

ローカルで再現するには:

```bash
zig build -Doptimize=ReleaseSmall
ls -lh zig-out/bin/nullclaw

/usr/bin/time -l zig-out/bin/nullclaw --help
/usr/bin/time -l zig-out/bin/nullclaw status
```

## ドキュメント

nullclaw のインストール、設定、運用、拡張への最短経路を知りたい場合は、ここから始めてください。

ローカライズされたドキュメントは `docs/en/` と `docs/zh/` にあります。以下のリンクから目的のページに直接移動できます。

| 目的 | English | 中文 |
|---|---|---|
| はじめに | [`docs/en/README.md`](docs/en/README.md) | [`docs/zh/README.md`](docs/zh/README.md) |
| インストール | [`docs/en/installation.md`](docs/en/installation.md) | [`docs/zh/installation.md`](docs/zh/installation.md) |
| Zig のインストール | [`docs/en/zig-installation.md`](docs/en/zig-installation.md) | [`docs/zh/zig-installation.md`](docs/zh/zig-installation.md) |
| 設定 | [`docs/en/configuration.md`](docs/en/configuration.md) | [`docs/zh/configuration.md`](docs/zh/configuration.md) |
| コマンド | [`docs/en/commands.md`](docs/en/commands.md) | [`docs/zh/commands.md`](docs/zh/commands.md) |
| 開発 | [`docs/en/development.md`](docs/en/development.md) | [`docs/zh/development.md`](docs/zh/development.md) |
| 運用 | [`docs/en/usage.md`](docs/en/usage.md) | [`docs/zh/usage.md`](docs/zh/usage.md) |
| アーキテクチャ | [`docs/en/architecture.md`](docs/en/architecture.md) | [`docs/zh/architecture.md`](docs/zh/architecture.md) |
| セキュリティ | [`docs/en/security.md`](docs/en/security.md) | [`docs/zh/security.md`](docs/zh/security.md) |
| Gateway API | [`docs/en/gateway-api.md`](docs/en/gateway-api.md) | [`docs/zh/gateway-api.md`](docs/zh/gateway-api.md) |

- 専門的なガイド: [`CONTRIBUTING.md`](CONTRIBUTING.md)、[`SECURITY.md`](SECURITY.md)、[`SIGNAL.md`](SIGNAL.md)

## 目的別の読み進め方

| 目的 | 最初に開くもの | 次に進む先 |
|---|---|---|
| 英語で初めて実行する | [`docs/en/README.md`](docs/en/README.md) | [`docs/en/installation.md`](docs/en/installation.md) → [`docs/en/configuration.md`](docs/en/configuration.md) → [`docs/en/usage.md`](docs/en/usage.md) |
| 中国語のクイックスタート（中文快速上手） | [`docs/zh/README.md`](docs/zh/README.md) | [`docs/zh/installation.md`](docs/zh/installation.md) → [`docs/zh/configuration.md`](docs/zh/configuration.md) → [`docs/zh/usage.md`](docs/zh/usage.md) |
| 適切な CLI コマンドを探す | [`docs/en/commands.md`](docs/en/commands.md) / [`docs/zh/commands.md`](docs/zh/commands.md) | `nullclaw help` → タスク別のサブコマンドページ |
| コードやドキュメントにコントリビュートする | [`CONTRIBUTING.md`](CONTRIBUTING.md) | [`docs/en/development.md`](docs/en/development.md) / [`docs/zh/development.md`](docs/zh/development.md) → 関連するアーキテクチャのページ |
| デプロイを運用・保護する | [`docs/en/usage.md`](docs/en/usage.md) / [`docs/zh/usage.md`](docs/zh/usage.md) | [`docs/en/security.md`](docs/en/security.md) / [`docs/zh/security.md`](docs/zh/security.md) → Gateway API |

## この README の次に

- 初めての方: [`docs/en/README.md`](docs/en/README.md) または [`docs/zh/README.md`](docs/zh/README.md) に移動し、案内された順序で読み進めてください。
- すぐにコマンドを知りたい方: [`docs/en/commands.md`](docs/en/commands.md) または [`docs/zh/commands.md`](docs/zh/commands.md) を開いてください。
- PR を送りたい方: まず [`CONTRIBUTING.md`](CONTRIBUTING.md) を読み、次に [`docs/en/development.md`](docs/en/development.md) または [`docs/zh/development.md`](docs/zh/development.md) を読んでください。

## クイックスタート

### 1) 推奨のインストール方法（Homebrew）

最も簡単な方法です。追加のランタイム依存関係なしで、すぐに実行できるバイナリをインストールします。

```bash
brew install nullclaw
nullclaw --help
```

### 2) ソースからビルドする

> **前提条件:** **Zig 0.16.0**（このバージョンちょうど）を使用してください。
> ほかのバージョンの Zig は現在サポートされておらず、ビルドに失敗する可能性があります。
> ビルド前に確認してください: `zig version` が `0.16.0` と表示される必要があります。
> 先に Zig が必要な Debian ユーザーは [`docs/en/zig-installation.md`](docs/en/zig-installation.md) を参照してください。

```bash
git clone https://github.com/nullclaw/nullclaw.git
cd nullclaw
zig build -Doptimize=ReleaseSmall
zig build test --summary all
```

`nullclaw` を `PATH` で使えるようにします:

macOS/Linux（zsh/bash）:

```bash
zig build -Doptimize=ReleaseSmall -p "$HOME/.local"
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.zshrc
# or ~/.bashrc
```

Windows（PowerShell）:

```powershell
zig build -Doptimize=ReleaseSmall -p "$HOME\.local"

$bin = "$HOME\.local\bin"
$user_path = [Environment]::GetEnvironmentVariable("Path", "User")
if (-not ($user_path -split ";" | Where-Object { $_ -eq $bin })) {
  [Environment]::SetEnvironmentVariable("Path", "$user_path;$bin", "User")
}
$env:Path = "$env:Path;$bin"
```

その後:

```bash
nullclaw --help
```

### 3) Docker Compose で実行する

このリポジトリには、ローカルでのコンテナ実行用に Docker Compose をラップした
Makefile が含まれています。

```bash
make build
make config
make up
```

`make config` はエージェントのコンテナ内で `nullclaw onboard --interactive` を実行します。
`CONFIG_ARGS` には機密情報を含まないフラグだけを渡してください:

```bash
make config CONFIG_ARGS="--provider openrouter"
```

API キーやボットトークンを `CONFIG_ARGS` に入れるのは避けてください。コマンドライン引数は
シェルの履歴やプロセス一覧から漏れる可能性があります。

compose のゲートウェイはデフォルトで `NULLCLAW_PORT=3210` を使い、コンテナ内では
`0.0.0.0` にバインドし、ホスト側では localhost に公開します:

```bash
curl http://127.0.0.1:3210/health
```

必要に応じて、ポートやホストのバインドアドレスを上書きできます:

```bash
make up NULLCLAW_PORT=8080
make up NULLCLAW_BIND=0.0.0.0
```

運用のショートカット:

```bash
make logs
make down
make shell
```

`NULLCLAW_BIND=0.0.0.0` は、ペアリング、Webhook シークレット、許可リスト、ホストの
ファイアウォールルールが設定された信頼できるネットワークでのみ設定してください。

### 4) よく使うコマンド

```bash

# Quick setup
nullclaw onboard --api-key sk-... --provider openrouter

# Or interactive wizard
nullclaw onboard --interactive

# Chat
nullclaw agent -m "Hello, nullclaw!"

# Interactive mode
nullclaw agent

# Start gateway runtime (gateway + all configured channels/accounts + heartbeat + scheduler)
nullclaw gateway                # default: 127.0.0.1:3000
nullclaw gateway --port 8080    # custom port

# Check status
nullclaw status

# Run system diagnostics
nullclaw doctor

# Check channel health
nullclaw channel status

# Start specific channels
nullclaw channel start telegram
nullclaw channel start discord
nullclaw channel start signal

# Manage background service
# Linux supports systemd user services and OpenRC
nullclaw service install
nullclaw service status

# Optional secret injection hook for service mode:
# if ~/.nullclaw/service-env is executable, the installed service launcher runs it
# before starting `nullclaw gateway` (for example via dotenvx or sops)

# Migrate memory from OpenClaw
nullclaw migrate openclaw --dry-run
nullclaw migrate openclaw
```

## エッジ MVP（ハイブリッドホスト + WASM ロジック）

エージェントのポリシーを WASM に保ったまま、Telegram + OpenAI でエッジデプロイ（Cloudflare Worker）を行いたい場合は、以下を参照してください:

`examples/edge/cloudflare-worker/`

このパターンでは、ネットワークとシークレットをエッジホスト側に置き、小さな Zig WASM モジュールを差し替えるだけでロジックを交換・更新できます。

## アーキテクチャ

すべてのサブシステムは **vtable インターフェース** です。設定を変更するだけで実装を差し替えられ、コードの変更は不要です。

| サブシステム | インターフェース | 同梱される実装 | 拡張 |
|-----------|-----------|------------|--------|
| **AI モデル** | `Provider` | 50 以上のプロバイダー（OpenRouter、Anthropic、OpenAI、Azure OpenAI、Gemini、Vertex AI、Ollama、Venice、NEAR AI Cloud、Atlas Cloud、Evolink、Eden AI、Groq、Mistral、xAI、DeepSeek、Together、Fireworks、Perplexity、Cohere、Bedrock、および多数の OpenAI 互換エンドポイント） | `custom:https://your-api.com` — 任意の OpenAI 互換 API |
| **チャンネル** | `Channel` | CLI、Telegram、Signal、Discord、Slack、iMessage、Matrix、WhatsApp、Webhook、IRC、Lark/Feishu、OneBot、Line、DingTalk、Email、Nostr、QQ、MaixCam、Mattermost | 任意のメッセージング API |
| **メモリ** | `Memory` | ハイブリッド検索（FTS5 + ベクトルのコサイン類似度）付きの SQLite、Markdown、ClickHouse、PostgreSQL、Redis、LanceDB、Lucid、LRU、API | 任意の永続化バックエンド |
| **ツール** | `Tool` | shell、file_read、file_write、file_edit、file_edit_hashed、file_read_hashed、file_append、memory_store、memory_recall、memory_forget、memory_list、browser_open、screenshot、composio、http_request、web_fetch、web_search、delegate、schedule、hardware_info、hardware_memory、pushover、message、spawn、git、image、i2c、spi など | 任意の機能 |
| **オブザーバビリティ** | `Observer` | Noop、Log、File、Multi | Prometheus、OTel |
| **ランタイム** | `RuntimeAdapter` | ネイティブ、Docker（サンドボックス化）、WASM（wasmtime） | 任意のランタイム |
| **セキュリティ** | `Sandbox` | Landlock、Firejail、Bubblewrap、Docker、自動検出 | 任意のサンドボックスバックエンド |
| **アイデンティティ** | `IdentityConfig` | OpenClaw（markdown）、AIEOS v1.1（JSON） | 任意のアイデンティティ形式 |
| **トンネル** | `Tunnel` | None、Cloudflare、Tailscale、ngrok、Custom | 任意のトンネルバイナリ |
| **ハートビート** | エンジン | HEARTBEAT.md による定期タスク | — |
| **スキル** | ローダー | TOML/JSON マニフェスト、または `SKILL.md` の YAML フロントマター | コミュニティのスキルパック |
| **周辺機器** | `Peripheral` | シリアル、Arduino、Raspberry Pi GPIO、STM32/Nucleo | 任意のハードウェアインターフェース |
| **Cron** | スケジューラー | Cron 式 + JSON 永続化付きのワンショットタイマー | — |

### メモリシステム

すべて独自実装で、コアパスには外部依存関係がありません:

| レイヤー | 実装 |
|-------|---------------|
| **ベクトル DB** | 埋め込みを SQLite に BLOB として保存し、コサイン類似度で検索 |
| **キーワード検索** | BM25 スコアリング付きの FTS5 仮想テーブル |
| **ハイブリッドマージ** | 重み付きマージ（ベクトル/キーワードの重みは設定可能） |
| **埋め込み** | `EmbeddingProvider` vtable — OpenAI、カスタム URL、または noop |
| **衛生管理** | 古いメモリの自動アーカイブと削除 |
| **スナップショット** | 移行用にメモリ全体の状態をエクスポート/インポート |
| **エンジン** | SQLite（デフォルト）、Markdown、ClickHouse、PostgreSQL、Redis、LanceDB、Lucid、LRU、API、None |

```json
{
  "memory": {
    "backend": "sqlite",
    "auto_save": true,
    "embedding_provider": "openai",
    "vector_weight": 0.7,
    "keyword_weight": 0.3,
    "hygiene_enabled": true,
    "snapshot_enabled": false
  }
}
```

## セキュリティ

nullclaw は **あらゆるレイヤー** でセキュリティを強制します。

| # | 項目 | 状態 | 方法 |
|---|------|--------|-----|
| 1 | **ゲートウェイを公開しない** | 完了 | デフォルトで `127.0.0.1` にバインドします。トンネルまたは明示的な `allow_public_bind` がない限り `0.0.0.0` を拒否します。 |
| 2 | **ペアリング必須** | 完了 | 起動時に 6 桁のワンタイムコードを発行します。`POST /pair` でベアラートークンと交換します。 |
| 3 | **ファイルシステムのスコープ制限** | 完了 | デフォルトで `workspace_only = true` です。ヌルバイトインジェクションをブロックします。シンボリックリンクによる脱出を検出します。 |
| 4 | **トンネル経由のアクセスのみ** | 完了 | アクティブなトンネルがない場合、ゲートウェイは公開バインドを拒否します。Tailscale、Cloudflare、ngrok、またはカスタムに対応します。 |
| 5 | **サンドボックスによる分離** | 完了 | Landlock、Firejail、Bubblewrap、Docker から最適なバックエンドを自動検出します。 |
| 6 | **暗号化されたシークレット** | 完了 | API キーはローカルのキーファイルを使い ChaCha20-Poly1305 で暗号化されます。 |
| 7 | **リソース制限** | 完了 | メモリ、CPU、ディスク、サブプロセスの制限を設定できます。 |
| 8 | **監査ログ** | 完了 | 保持期間を設定できる署名付きのイベント記録です。 |

### チャンネルの許可リスト

- 空の許可リスト = **すべての受信メッセージを拒否**
- `"*"` = **すべて許可**（明示的なオプトイン）
- それ以外 = 完全一致の許可リスト

Nostr ではさらに、`dm_allowed_pubkeys` にかかわらず `owner_pubkey` は **常に** 許可されます。秘密鍵は SecretStore（`enc2:` プレフィックス）によって保存時に暗号化され、チャンネルの実行中にのみメモリ上で復号されます。チャンネルの停止時にはゼロクリアされます。

### Nostr チャンネルのセットアップ

`nullclaw` は [`nak`](https://github.com/fiatjaf/nak) を使い、NIP-17（ギフトラップされたプライベート DM）と NIP-04（レガシー DM）によって Nostr にネイティブ対応しています。

**前提条件:** `nak` をインストールし、`$PATH` に含まれていることを確認してください。

**オンボーディングウィザードでのセットアップ:**

```bash
nullclaw onboard --interactive   # Step 7 configures Nostr
```

ウィザードでは次のことを行います:
1. ボット用の新しい鍵ペアを生成するか、鍵をインポートして ChaCha20-Poly1305 で暗号化する
2. あなた（オーナー）の公開鍵（npub または hex）を尋ねる — DM ポリシーで常に許可されます
3. リレーと DM リレー（kind:10050 の受信箱）を設定する
4. ボットの公開鍵を表示する

または、[設定](#設定) で手動で設定することもできます。

**仕組み:** 起動時に nullclaw は DM 受信箱のリレー（kind:10050）を告知し、受信する NIP-17 ギフトラップと NIP-04 の暗号化 DM を待ち受けます。送信メッセージは送信者のプロトコルに合わせます。複数リレーにまたがる rumor の重複排除により、同じメッセージが複数のリレーから届いても重複した応答を防ぎます。

## 設定

設定ファイル: `~/.nullclaw/config.json`（`onboard` によって作成されます）

> **OpenClaw 互換:** nullclaw は [OpenClaw](https://github.com/openclaw/openclaw) と同じ設定構造（snake_case）を使います。プロバイダーは `models.providers` の下に、デフォルトモデルは `agents.defaults.model.primary` の下に置き、チャンネルは `accounts` ラッパーを使います。
> トップレベルの `default_provider` / `default_model` キーはサポートされていません。
>
> **Vertex AI に関する注意:** `models.providers.vertex.api_key` には次のどちらかを指定できます:
> 1. ベアラートークン（`ya29...`）、または
> 2. Google サービスアカウントの JSON オブジェクト全体（`project_id`、`client_email`、`private_key` を含む、Apps Script の `GEMINI_KEY` と同じ形式）。
>
> `models.providers.vertex.base_url` は明示的に設定する（`.../projects/<id>/locations/<loc>/publishers/google/models`）ことも、サービスアカウントの JSON を使う場合は省略することもできます（nullclaw が `project_id` から導出し、`VERTEX_LOCATION` のデフォルトは `global` です）。
> サービスアカウントモードでは、RS256 JWT の署名のために `$PATH` で `openssl` が使える必要があります。

```json
{
  "default_temperature": 0.7,

  "models": {
    "providers": {
      "openrouter": { "api_key": "sk-or-..." },
      "nearai": { "api_key": "YOUR_NEARAI_API_KEY" },
      "atlas-cloud": { "api_key": "YOUR_ATLASCLOUD_API_KEY" },
      "evolink": { "api_key": "YOUR_EVOLINK_API_KEY" },
      "edenai": { "api_key": "YOUR_EDENAI_API_KEY" },
      "groq": { "api_key": "gsk_..." },
      "azure": { "api_key": "YOUR_AZURE_OPENAI_API_KEY", "base_url": "https://your-resource.openai.azure.com" },
      "vertex": {
        "api_key": {
          "type": "service_account",
          "project_id": "your-project",
          "client_email": "svc@your-project.iam.gserviceaccount.com",
          "private_key": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n"
        },
        "base_url": "https://aiplatform.googleapis.com/v1/projects/your-project/locations/global/publishers/google/models"
      },
      "anthropic": { "api_key": "sk-ant-..." }
    }
  },

  "agents": {
    "defaults": {
      "model": { "primary": "openrouter/anthropic/claude-sonnet-4" },
      "heartbeat": { "every": "30m" }
    },
    "list": [
      { "id": "researcher", "model": { "primary": "openrouter/anthropic/claude-opus-4" }, "system_prompt": "..." }
    ]
  },

  "channels": {
    "telegram": {
      "accounts": {
        "main": {
          "bot_token": "123:ABC",
          "allow_from": ["user1"],
          "reply_in_private": true,
          "proxy": "socks5://..."
        }
      }
    },
    "discord": {
      "accounts": {
        "main": {
          "token": "disc-token",
          "guild_id": "12345",
          "allow_from": ["user1"],
          "allow_bots": false
        }
      }
    },
    "irc": {
      "accounts": {
        "main": {
          "host": "irc.libera.chat",
          "port": 6697,
          "nick": "nullclaw",
          "channels": ["#nullclaw"],
          "tls": true,
          "allow_from": ["user1"]
        },
        "meshrelay": {
          "host": "irc.meshrelay.xyz",
          "port": 6697,
          "nick": "nullclaw",
          "channels": ["#agents"],
          "tls": true,
          "nickserv_password": "YOUR_NICKSERV_PASSWORD",
          "allow_from": ["*"]
        }
      }
    },
    "slack": {
      "accounts": {
        "main": {
          "bot_token": "xoxb-...",
          "app_token": "xapp-...",
          "allow_from": ["user1"]
        }
      }
    },
    "nostr": {
      "private_key": "enc2:...",
      "owner_pubkey": "hex-pubkey-of-owner",
      "relays": ["wss://relay.damus.io", "wss://nos.lol", "wss://relay.nostr.band"],
      "dm_allowed_pubkeys": ["*"],
      "display_name": "NullClaw",
      "about": "AI assistant on Nostr",
      "nip05": "nullclaw@yourdomain.com",
      "lnurl": "lnurl1..."
    }
  },

  "tools": {
    "media": {
      "audio": {
        "enabled": true,
        "language": "ru",
        "models": [{ "provider": "groq", "model": "whisper-large-v3" }]
      }
    }
  },

  "mcp_servers": {
    "filesystem": {
      "transport": "stdio",
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem"],
      "timeout_ms": 10000
    },
    "remote": {
      "transport": "http",
      "url": "https://mcp.example.com/rpc",
      "timeout_ms": 10000,
      "headers": {
        "Authorization": "Bearer example-token"
      }
    }
  },

  "memory": {
    "backend": "sqlite",
    "auto_save": true,
    "embedding_provider": "openai",
    "vector_weight": 0.7,
    "keyword_weight": 0.3
  },

  "gateway": {
    "port": 3000,
    "require_pairing": true,
    "allow_public_bind": false
  },

  "autonomy": {
    "level": "supervised",
    "workspace_only": true,
    "max_actions_per_hour": 20
  },

  "runtime": {
    "kind": "native",
    "docker": {
      "image": "alpine:3.24",
      "network": "none",
      "memory_limit_mb": 512,
      "read_only_rootfs": true
    }
  },


  "tunnel": { "provider": "none" },
  "secrets": { "encrypt": true },
  "identity": { "format": "openclaw" },

  "security": {
    "sandbox": { "backend": "auto" },
    "resources": { "max_memory_mb": 512, "max_cpu_percent": 80 },
    "audit": { "enabled": true, "retention_days": 90 }
  }
}
```

設定値はリテラルとして扱われます。NullClaw は `config.json` の文字列内（カスタムヘッダーの値を含む）で
`${VAR}` を展開しません。環境変数ベースのシークレットが必要な場合は、
独自のデプロイツールで事前に `config.json` を生成してください。
MCP の `timeout_ms` は各 HTTP または stdio リクエストの上限です。タイムアウトした stdio サーバーは
ランチャーのプロセスグループごと終了されるため、ブロックされた子プロセスが残ることはありません。

Telegram のフォーラムトピック:

- トピックごとのセッション分離は自動です。`channels.telegram` の下に `topic_id` フィールドを追加する必要はありません。
- 最も簡単な運用手順は次のとおりです:
  1. `agents.list` の下に名前付きのエージェントプロファイルを定義する
  2. 対象の Telegram チャットまたはフォーラムトピックを開く
  3. `/bind <agent>` を実行する
- 特定の Telegram フォーラムトピックを特定のエージェントにバインドするには、正規のスレッド形式 `"<chat_id>:thread:<topic_id>"` で `bindings[].match.peer.id` を使用します。
- ほかのすべてのトピックのフォールバックとして Telegram グループ全体をバインドするには、`"<chat_id>"` による通常のグループバインディングを残しておきます。
- `/bind status` は現在有効なルートと利用可能なエージェント ID を表示します。
- `/bind clear` は現在のアカウント/チャット/トピックに完全一致するバインディングだけを削除し、より広いルートにフォールバックします。
- `/bind` は現在の Telegram アカウントとピアに対する完全一致の `bindings[]` エントリを永続化します。
- `/bind status` は、完全一致のローカルな上書きと、継承されたより広いフォールバックを区別して表示します。
- トピック固有のバインディングは、ルートの優先度によってグループのフォールバックより優先されます。`bindings[]` 内の順序は関係ありません。
- `/bind` を Telegram のメニューに表示するかどうかは `channels.telegram.accounts.<id>.binding_commands_enabled` で制御します。

例:

```json
{
  "bindings": [
    {
      "agent_id": "coder",
      "match": {
        "channel": "telegram",
        "account_id": "main",
        "peer": { "kind": "group", "id": "-1001234567890:thread:42" }
      }
    },
    {
      "agent_id": "orchestrator",
      "match": {
        "channel": "telegram",
        "account_id": "main",
        "peer": { "kind": "group", "id": "-1001234567890" }
      }
    }
  ]
}
```

この設定では、トピック `42` は `coder` にルーティングされ、フォーラムの残りは `orchestrator` にフォールバックします。

名前付きのエージェントプロファイルはバインディングとは別に設定します。バインディングは、どの名前付きエージェントが特定のチャット/トピックを処理するかを選ぶだけです。

名前付きのエージェントを専用のワークスペースで実行したい場合は、`agents.list[].workspace_path` を設定してください。
相対パスは `config.json` を含むディレクトリから解決され、ワークスペースは初回使用時に作成され、エージェントには永続的なメモリ名前空間 `agent:<agent-id>` が割り当てられます。
`workspace_path` を設定しても `system_prompt` は無効になりません。両方が設定されている場合、名前付きプロファイルのプロンプトも適用され、ワークスペースのブートストラップファイルはその専用ワークスペースから読み込まれます。
これは `nullclaw agent --agent <id>`、`/subagents spawn --agent <id>`、および `bindings` によって解決されるルーティングされたセッションに適用されます。

最小限のエンドツーエンドの例:

```json
{
  "agents": {
    "list": [
      {
        "id": "orchestrator",
        "provider": "openrouter",
        "model": "anthropic/claude-sonnet-4"
      },
      {
        "id": "coder",
        "provider": "ollama",
        "model": "qwen2.5-coder:14b",
        "system_prompt": "You are the coding agent for this topic."
      }
    ]
  },
  "channels": {
    "telegram": {
      "accounts": {
        "main": {
          "bot_token": "123456:ABCDEF",
          "allow_from": ["YOUR_TELEGRAM_USER_ID"],
          "binding_commands_enabled": true,
          "topic_commands_enabled": true,
          "topic_map_command_enabled": true,
          "commands_menu_mode": "scoped"
        }
      }
    }
  },
  "bindings": [
    {
      "agent_id": "orchestrator",
      "match": {
        "channel": "telegram",
        "account_id": "main",
        "peer": { "kind": "group", "id": "-1001234567890" }
      }
    }
  ]
}
```

運用手順:

- 対象のフォーラムトピック内で `/bind coder` を送信します。
- `nullclaw` は、そのトピックと Telegram アカウントに対する新しい完全一致の `bindings[]` エントリを `~/.nullclaw/config.json` に書き込みます。
- そのトピックの次のメッセージから、新しくルーティングされたエージェントプロファイルが使われます。
- `/bind` で変更を永続化するには、`nullclaw` が `~/.nullclaw/config.json` への書き込み権限を持っている必要があります。

`account_id` について:

- `account_id` は設定済みの Telegram アカウントのエントリを識別するもので、トピックやエージェントを識別するものではありません。
- 通常の `channels.telegram.accounts` 形式では、オブジェクトのキーがアカウント ID になります。たとえば、`accounts.main` は `account_id = "main"`、`accounts.backup` は `account_id = "backup"` を意味します。
- `bindings` では、`match.account_id` がそのバインディングを特定の 1 つの Telegram アカウントに限定します。
- `match.account_id` を省略すると、バインディングはそのチャンネルの任意の Telegram アカウントにマッチします。
- 異なるアカウント ID を使うのは、同じ nullclaw インスタンスで複数の Telegram ボットアカウント/トークンを運用する場合だけにしてください。

配信への影響:

- 受信した Telegram の更新は、それを受け取ったアカウントによって処理されます。
- ルーティングには同じ `account_id` が使われるため、`match.account_id = "main"` は `channels.telegram.accounts.main` が受け取ったメッセージにだけマッチします。
- 返信は、そのメッセージを処理したのと同じ Telegram アカウント/ランタイムから送信されます。
- あるバインディングを `account_id = "main"` に、別のバインディングを `account_id = "sub"` に設定しても、1 つのチャットが自動的に 2 つのエージェントに分割されるわけではありません。各バインディングが、それぞれ異なる設定済みの Telegram アカウントにスコープされるだけです。

### 完全な Web 検索 + シェルアクセス

Web 検索プロバイダーを完全に制御し、シェルコマンドの許可リストを無制限にしたい場合に使用します:

```json
{
  "http_request": {
    "enabled": true,
    "search_base_url": "https://searx.example.com",
    "search_provider": "auto",
    "search_fallback_providers": ["jina", "duckduckgo"]
  },
  "autonomy": {
    "level": "full",
    "allowed_commands": ["*"],
    "allowed_paths": ["*"],
    "require_approval_for_medium_risk": false,
    "block_medium_risk_commands": false,
    "block_high_risk_commands": false
  }
}
```

- `http_request.search_base_url` には、インスタンスのルート（`https://host`）または明示的なエンドポイント（`https://host/search`）を指定できます。ローカル/プライベートな SearXNG インスタンスでは、`http://localhost:8888` や `http://192.168.1.10:8888/search` のようにプレーンな HTTP も使えます。
- 不正な `http_request.search_base_url` は、起動時の設定検証で失敗するようになりました（不正な URL に対する自動フォールバックはありません）。
- `http_request.search_provider` は `auto`、`searxng`、`duckduckgo`（`ddg`）、`brave`、`firecrawl`、`tavily`、`perplexity`、`exa`、`jina` に対応しています。
- `http_request.search_fallback_providers` は任意で、プライマリのプロバイダーが失敗したときに順番に試されます。
- プロバイダーの環境変数: `BRAVE_API_KEY`、`FIRECRAWL_API_KEY`、`TAVILY_API_KEY`、`PERPLEXITY_API_KEY`、`EXA_API_KEY`、`JINA_API_KEY`（対応している場合は共通の `WEB_SEARCH_API_KEY`）。DuckDuckGo と SearXNG には API キーは不要です。
- `allowed_commands` のエントリは `"cmd"`、`"cmd *"`、`"*"` の形式に対応しています。
  - `"cmd"` と `"cmd *"` はどちらも、許可リストの段階でそのコマンドファミリーを許可します。
  - `"*"` は許可リストの段階で任意のコマンドを許可します。
- 許可リストのチェック後も、高リスクと中リスクのランタイムゲートは適用されます。`curl`/`wget` のようなネットワーク/転送コマンドや、その他の中リスクの変更を意図的に許可する場合は、`block_medium_risk_commands: false` を設定してください。
- `allowed_paths: ["*"]` は、システムで保護されたパスを除き、ワークスペース外へのアクセスを許可します。

### Web UI / ブラウザーリレー

ブラウザー UI のイベント（WebChannel v1）には `channels.web` を使用します:

```json
{
  "channels": {
    "web": {
      "accounts": {
        "default": {
          "transport": "local",
          "listen": "127.0.0.1",
          "port": 32123,
          "path": "/ws",
          "auth_token": "replace-with-long-random-token",
          "message_auth_mode": "pairing",
          "allowed_origins": ["http://localhost:5173", "chrome-extension://your-extension-id"]
        }
      }
    }
  }
}
```

- ローカル: `"listen": "127.0.0.1"` のままにしてください。
- `message_auth_mode` は受信する `user_message` の認証を制御します:
  - `"pairing"`（デフォルト）: `pairing_request` を送信して `pairing_result` を受け取り、すべての `user_message` に UI の `access_token` を含めます。
  - `"token"`（ローカルトランスポートのみ）: 各 `user_message` のペイロードに `auth_token` を含めます（互換性のため `access_token` も受け付けます）。
- `auth_token` は WebSocket のアップグレードを強化し、ループバック以外のアドレスにバインドする場合は必須になります。
- 認証なしの WebSocket アップグレードはループバックでのみ可能です。ペアリング優先のローカル UX は `127.0.0.1` で動作しますが、公開/LAN へのバインドでは、最初のホップで `?token=<auth_token>` または `Authorization: Bearer <auth_token>` によって `/ws` のアップグレードを認証する必要があります。
- ローカルのループバックでのペアリングは、固定の共有コードに依存しなくなりました。`pairing_request` では `payload.pairing_code` を省略でき、いまだに `123456` を送信するレガシーなループバッククライアントとも互換性があります。
- `/ws` は WebSocket エンドポイントです。`/pair` は HTTP ゲートウェイ API に属し、Web チャンネルのハンドシェイクには含まれません。
- リモート/ヘッドレスのホスト: `"listen": "0.0.0.0"` にバインドする場合は、TLS/リバースプロキシの背後で、安定した設定済みトークンと `message_auth_mode: "token"` を使うことをおすすめします。または、ループバックへのバインドを維持し、SSH トンネル/プロキシ経由で公開してください。
- UI/拡張機能は別のリポジトリに置き、この WebSocket エンドポイント経由で接続してください。
- オーケストレーションには、設定または環境変数（`NULLCLAW_WEB_TOKEN`、`NULLCLAW_GATEWAY_TOKEN`、`OPENCLAW_GATEWAY_TOKEN`）の安定したトークンを使うローカルのトークンモードを使用してください。
- リレートランスポート（送信側のエージェントソケット）は次のように設定します:

```json
{
  "channels": {
    "web": {
      "accounts": {
        "default": {
          "transport": "relay",
          "relay_url": "wss://relay.nullclaw.io/ws/agent",
          "relay_agent_id": "default",
          "relay_token": "replace-with-relay-token",
          "relay_token_ttl_secs": 2592000,
          "relay_pairing_code_ttl_secs": 300,
          "relay_ui_token_ttl_secs": 86400,
          "relay_e2e_required": false
        }
      }
    }
  }
}
```

- リレートークンのライフサイクル（専用）: `relay_token`（設定）-> `NULLCLAW_RELAY_TOKEN`（環境変数）-> 永続化された `web-relay-<account_id>` 認証情報 -> 生成されたトークン。
- リレー UI のハンドシェイク: ワンタイムの `pairing_code` を含む `pairing_request` を送信し、UI の `access_token` JWT（およびリレーの HTTP レイヤー用の任意の `set_cookie` 文字列）を含む `pairing_result` を受け取ります。
- リレーの `user_message` には、`access_token`（トップレベルまたは `payload.access_token`）に有効な UI JWT を含める必要があります。
- E2E が有効な場合（`relay_e2e_required=true`）、UI とエージェントはペアリング中に X25519 の鍵を交換し、暗号化されたペイロードを `payload.e2e` で送信します。
- WebChannel のイベントエンベロープは [`spec/webchannel_v1.json`](spec/webchannel_v1.json) で定義されています。

## Gateway API

| エンドポイント | メソッド | 認証 | 説明 |
|----------|--------|------|-------------|
| `/health` | GET | なし | ヘルスチェック（常に公開） |
| `/pair` | POST | `X-Pairing-Code` ヘッダー | ワンタイムコードをベアラートークンと交換 |
| `/webhook` | POST | `Authorization: Bearer <token>` | メッセージを送信: `{"message": "your prompt"}` |
| `/media/transcribe` | POST | `Authorization: Bearer <token>` | 設定済みの STT で `audio_base64` ペイロードを文字起こし |
| `/.well-known/agent-card.json` | GET | なし | A2A Agent Card の検出（公開） |
| `/a2a` | POST | `Authorization: Bearer <token>` | A2A JSON-RPC エンドポイント（正規のメソッドとレガシーのスラッシュエイリアス） |
| `/whatsapp` | GET | クエリパラメーター | Meta の Webhook 検証 |
| `/whatsapp` | POST | なし（Meta の署名） | WhatsApp の受信メッセージ Webhook |

### A2A（Agent-to-Agent Protocol v0.3.0）

NullClaw は Google の [A2A プロトコル](https://github.com/google/A2A) v0.3.0 を実装しており、A2A 互換のエージェントやクライアントが JSON-RPC 2.0 経由でインスタンスを検出、認証し、やり取りできます。

`~/.nullclaw/config.json` で有効にします:

```json
{
  "a2a": {
    "enabled": true,
    "name": "nullclaw",
    "description": "General-purpose AI assistant",
    "url": "https://example.com",
    "version": "1.0.0"
  }
}
```

**エンドポイント:**

| エンドポイント | 認証 | 説明 |
|----------|------|-------------|
| `GET /.well-known/agent-card.json` | なし | Agent Card の検出（公開） |
| `POST /a2a` | ベアラートークン | JSON-RPC 2.0 のディスパッチ |

**対応メソッド:** `message/send`、`message/stream`、`tasks/get`、`tasks/cancel`、`tasks/list`、`tasks/resubscribe`。

**簡単なテスト:**

```bash
# 1. Get a bearer token
# Set PAIRING_CODE to the one-time code for this gateway session.
TOKEN=$(curl -s -X POST -H "X-Pairing-Code: $PAIRING_CODE" http://localhost:3000/pair | jq -r .token)

# 2. Discover the agent
curl http://localhost:3000/.well-known/agent-card.json

# 3. Send a message
curl -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"message/send","params":{"message":{"messageId":"msg-1","role":"user","parts":[{"kind":"text","text":"Hello"}]}}}' \
  http://localhost:3000/a2a
```

ストリーミング、タスクのライフサイクル、設定の詳細を含む A2A の完全なリファレンスは、[Gateway API ドキュメント](docs/en/gateway-api.md) を参照してください。

### メディアの文字起こし

`POST /media/transcribe` は `audio_base64`、`mime_type`、`source`、および任意の `language` を含む JSON を受け取り、`{"text":"..."}` とメタデータを返します。STT は `tools.media.audio` の下で設定します。リモートのカスタム STT エンドポイントは HTTPS を使う必要があります。デスクトップ音声をライブでチャンク処理する場合は、`gateway.max_body_size_bytes`、`gateway.request_timeout_secs`、`gateway.webhook_rate_limit_per_minute` を引き上げてください。

## コマンド

| コマンド | 説明 |
|---------|-------------|
| `onboard --api-key sk-... --provider openrouter` | API キーとプロバイダーを指定したクイックセットアップ |
| `onboard --interactive` | 完全な対話型ウィザード |
| `onboard --channels-only` | チャンネル/許可リストだけを再設定 |
| `agent -m "..."` | 単一メッセージモード |
| `acp` | ACP 互換エディター向けに Agent Client Protocol の stdio アダプターを起動 |
| `agent` | 対話型チャットモード |
| `gateway` | 長時間実行のランタイムを起動（デフォルト: `127.0.0.1:3000`） |
| `service install\|start\|stop\|restart\|status\|uninstall` | バックグラウンドサービスを管理 |
| `doctor` | システムの健全性を診断 |
| `status [--json]` | システム全体の状態を表示、または機械可読なランタイムのスナップショットを出力 |
| `channel list\|info\|start\|status\|add\|remove` | チャンネルを管理（自動化向けの JSON アカウント一覧を含む） |
| `cron list\|status\|add\|add-agent\|once\|once-agent\|remove\|pause\|resume\|run\|update\|runs` | スケジュールされたタスクを管理 |
| `skills list\|install\|remove\|info` | スキルパックを管理（`install --name <query>` によるレジストリ検索を含む） |
| `history list\|show` | セッションの会話履歴を表示 |
| `memory stats\|count\|reindex\|search\|get\|list\|export-jsonl\|hygiene-report\|drain-outbox\|forget` | メモリの調査、エクスポート、保守 |
| `hardware scan\|flash\|monitor` | ハードウェアデバイスの管理 |
| `config show\|get`, `models list\|summary\|info\|benchmark\|refresh` | 設定/モデルの管理状態を読み取り、モデルカタログを管理 |
| `workspace edit\|reset-md` | ワークスペースの markdown/ブートストラップファイルを保守 |
| `capabilities [--json]` | ランタイムの機能マニフェストを表示 |
| `auth login\|status\|logout` | OAuth 認証を管理 |
| `migrate openclaw [--dry-run] [--source PATH]` | OpenClaw からメモリをインポートし、設定を移行 |
| `update [--check] [--yes]` | アップデートを確認してインストール |

## 開発

ビルドとテストは **Zig 0.16.0** に固定されています。

```bash
zig build                          # Dev build
zig build -Doptimize=ReleaseSmall  # Release build (678 KB)
zig build test --summary all       # 5,300+ tests
```

### チャンネルフローのカバレッジ

チャンネルの CJM カバレッジ（受信のパース/フィルタリング、セッションキーのルーティング、アカウントの伝播、バスへの受け渡し）は、以下のテストで検証されています:

- `src/channel_manager.zig`（ランタイムのチャンネル登録/起動のセマンティクス + リスナーモードの配線）
- `src/config.zig`（OpenClaw 互換の `channels.*.accounts` のパース、マルチアカウントの選択/順序、エイリアス）
- `src/gateway.zig`（Webhook のペイロードからの Telegram/WhatsApp/LINE/Lark のルーティング済みセッションキー）
- `src/daemon.zig`（Discord/QQ/OneBot/Mattermost/MaixCam のゲートウェイループでの受信ルート解決）
- `src/channels/discord.zig`、`src/channels/mattermost.zig`、`src/channels/qq.zig`、`src/channels/onebot.zig`、`src/channels/signal.zig`、`src/channels/line.zig`、`src/channels/whatsapp.zig`（チャンネルごとの受信/送信の契約）

### プロジェクトの統計

```
Language:     Zig 0.16.0
Source files: ~250
Lines of code: ~249,000
Tests:        5,300+
Binary:       678 KB (ReleaseSmall)
Peak RSS:     ~1 MB
Startup:      <2 ms (Apple Silicon)
Dependencies: 0 (besides libc + optional SQLite)
```

### ソースの構成

```
src/
  main.zig              CLI entry point + argument parsing
  root.zig              Module hierarchy (public API)
  config.zig            JSON config loader + 30 sub-config structs
  agent.zig             Agent loop, auto-compaction, tool dispatch
  daemon.zig            Daemon supervisor with exponential backoff
  gateway.zig           HTTP gateway (rate limiting, idempotency, pairing)
  channels/             19 channel implementations (telegram, signal, discord, slack, nostr, matrix, whatsapp, line, lark, onebot, mattermost, qq, ...)
  providers/            50+ AI provider integrations
  memory/               SQLite backend, embeddings, vector search, hygiene, snapshots
  tools/                35+ tool implementations
  security/             Secrets (ChaCha20), sandbox backends (landlock, firejail, ...)
  cron.zig              Cron scheduler with JSON persistence
  health.zig            Component health registry
  tunnel.zig            Tunnel vtable (cloudflare, ngrok, tailscale, custom)
  peripherals.zig       Hardware peripheral vtable (serial, Arduino, RPi, Nucleo)
  runtime.zig           Runtime vtable (native, docker, WASM)
  skillforge.zig        Skill discovery (GitHub), evaluation, integration
  ...
```

## バージョニング

nullclaw はリリースに **CalVer**（`YYYY.M.D`）を使用しています。例: `v2026.2.20`。

- **タグの形式:** `vYYYY.M.D`（リリースは 1 日最大 1 回。必要に応じてパッチ用のサフィックス `vYYYY.M.D.N`）
- **リリースバイナリに埋め込まれるバージョンは git タグから導出されます**（`v...` -> `nullclaw --version`）
- **リリース以外のビルドのデフォルトは `dev` です**（`zig build -Dversion=...` で上書きしない限り）
- **安定性の保証はまだありません** — プロジェクトは 1.0 より前の段階で、設定や CLI はリリース間で変更される可能性があります
- **`nullclaw --version`** で現在のバージョンを表示します

## コントリビュート

開発環境のセットアップ、ワークフロー、検証コマンド、PR チェックリストについては [`CONTRIBUTING.md`](CONTRIBUTING.md) を参照してください。

vtable インターフェースを実装して、PR を送ってください:

- 新しい `Provider` -> `src/providers/`
- 新しい `Channel` -> `src/channels/`
- 新しい `Tool` -> `src/tools/`
- 新しい `Memory` バックエンド -> `src/memory/`
- 新しい `Tunnel` -> `src/tunnel.zig`
- 新しい `Sandbox` バックエンド -> `src/security/`
- 新しい `Peripheral` -> `src/peripherals.zig`
- 新しい `Skill` -> `~/.nullclaw/workspace/skills/<name>/` または `~/.nullclaw/workspace/skills/<category>/<name>/`

## 中国語ドキュメント（中文文档）

- [中国語ドキュメントの概要（中文文档总览）](docs/zh/README.md)
- [インストールガイド（安装指南）](docs/zh/installation.md)
- [Zig のインストール（Zig 安装指南）](docs/zh/zig-installation.md)
- [設定ガイド（配置指南）](docs/zh/configuration.md)
- [使い方と運用（使用与运维）](docs/zh/usage.md)
- [アーキテクチャの概要（架构总览）](docs/zh/architecture.md)
- [セキュリティモデル（安全机制）](docs/zh/security.md)
- [Gateway API（中文）](docs/zh/gateway-api.md)
- [コマンドリファレンス（命令参考）](docs/zh/commands.md)
- [開発ガイド（开发指南）](docs/zh/development.md)

## 英語ドキュメント

- [英語ドキュメントの概要](docs/en/README.md)
- [インストール](docs/en/installation.md)
- [Zig のインストール](docs/en/zig-installation.md)
- [設定](docs/en/configuration.md)
- [使い方と運用](docs/en/usage.md)
- [アーキテクチャ](docs/en/architecture.md)
- [セキュリティ](docs/en/security.md)
- [Gateway API](docs/en/gateway-api.md)
- [コマンド](docs/en/commands.md)
- [開発](docs/en/development.md)

## 免責事項

nullclaw は純粋なオープンソースソフトウェアプロジェクトです。いかなる種類の **トークン、暗号資産、ブロックチェーンのコンポーネント、金融商品もありません**。このプロジェクトは、いかなるトークンや金融商品とも関係がありません。

## ライセンス

MIT — [LICENSE](LICENSE) を参照してください

---

**nullclaw** — オーバーヘッドはゼロ。妥協もゼロ。どこにでもデプロイ。何でも差し替え可能。

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=nullclaw/nullclaw&type=date&legend=top-left)](https://www.star-history.com/#nullclaw/nullclaw&type=date&legend=top-left)
