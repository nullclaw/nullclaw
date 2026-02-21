# NullClaw × Discord × Claude セットアップガイド

このフォークは NullClaw に Discord ゲートウェイサポートを追加したものです。
Zig 0.15.2 互換パッチ込み。Milk-V Duo 256M（RISC-V）で動作確認済み。

---

## 目次

1. [変更内容](#変更内容)
2. [必要なもの](#必要なもの)
3. [ステップ1 — Zig 0.15.2 のインストール（ビルドマシン）](#ステップ1--zig-0152-のインストール)
4. [ステップ2 — このリポジトリをクローンしてビルド](#ステップ2--クローンとビルド)
5. [ステップ3 — RISC-V 機器へのインストール](#ステップ3--risc-v-機器へのインストール)
6. [ステップ4 — Claude 認証キーを取得する](#ステップ4--claude-認証キーを取得する)
7. [ステップ5 — Discord Bot を作成する](#ステップ5--discord-bot-を作成する)
8. [ステップ6 — NullClaw を設定する](#ステップ6--nullclaw-を設定する)
9. [ステップ7 — 動作確認](#ステップ7--動作確認)
10. [ステップ8 — systemd サービスとして常駐させる](#ステップ8--systemd-サービスとして常駐させる)
11. [トラブルシューティング](#トラブルシューティング)
12. [アーキテクチャ](#アーキテクチャ)

---

## 変更内容

このフォークで変更したファイルは 4 つです。

| ファイル | 変更内容 |
|---------|---------|
| `src/channel_loop.zig` | `DiscordLoopState` と `runDiscordLoop` を追加（WebSocket → event bus → AI → REST の一連の流れ） |
| `src/daemon.zig` | `channelSupervisorThread` に Discord 管理スレッドを追加 |
| `src/channels/discord.zig` | `posix.close()` が void を返す Zig 0.15.2 の変更に対応 |
| `src/websocket.zig` | HTTP アップグレードレスポンスを 1 バイトずつ読むよう変更（HELLO フレームの取りこぼし防止）、`Io.Reader.readSliceShort` への移行 |

**なぜ websocket.zig を修正したか：**
`readSliceShort` は TLS バッファに溜まったデータをまとめて返すため、HTTP 101 レスポンスと Discord が直後に送る HELLO フレームを一緒に読み込んでしまいます。HELLO のデータが捨てられると、次の `readTextMessage()` が永久にブロックし、約 60 秒後に TCP タイムアウトで切れます。1 バイトずつ読んで `\r\n\r\n` で止めることで解決しました。

---

## 必要なもの

| 項目 | 要件 |
|------|------|
| ターゲット機器 | RISC-V 64bit Linux（Milk-V Duo 256M など） |
| ターゲット OS | Debian 13 (trixie) 推奨 |
| ビルドマシン | x86_64 Linux（クロスコンパイル用） |
| Zig | **0.15.2**（他バージョン不可） |
| Claude 認証 | Claude Pro/Max のセットアップトークン、または通常 API キー |
| Discord Bot | Discord Developer Portal で作成した Bot トークン |

---

## ステップ1 — Zig 0.15.2 のインストール

**ビルドマシン（x86_64 Linux）で実行します。**

```bash
cd /tmp
curl -LO https://ziglang.org/download/0.15.2/zig-x86_64-linux-0.15.2.tar.xz
tar xf zig-x86_64-linux-0.15.2.tar.xz

# パスを確認
/tmp/zig-x86_64-linux-0.15.2/zig version
# => 0.15.2
```

> **注意**: `apt` 等でインストールできる Zig は古いバージョンのことが多いです。必ず公式から 0.15.2 を取得してください。

---

## ステップ2 — クローンとビルド

```bash
# このフォークをクローン
git clone https://github.com/YOUR_GITHUB_USERNAME/nullclaw.git
cd nullclaw
git checkout discord-daemon-integration

# RISC-V 向けにクロスコンパイル
/tmp/zig-x86_64-linux-0.15.2/zig build \
  -Dtarget=riscv64-linux \
  -Doptimize=ReleaseSmall

# ビルド成果物の確認
ls -lh zig-out/bin/nullclaw
# => -rwxr-xr-x ... 1.9M ... zig-out/bin/nullclaw
file zig-out/bin/nullclaw
# => ELF 64-bit LSB executable, UCB RISC-V, ...
```

**成果物**: `zig-out/bin/nullclaw`
- RISC-V 64bit ELF バイナリ
- 完全静的リンク（依存ライブラリなし）
- サイズ約 1.9 MB

ビルドに失敗する場合は [トラブルシューティング](#トラブルシューティング) を参照してください。

---

## ステップ3 — RISC-V 機器へのインストール

**ビルドマシンから実行します。**

```bash
# SCP でコピー（IP アドレスは適宜変更）
scp zig-out/bin/nullclaw debian@192.168.1.100:/home/debian/nullclaw

# SSH でログイン
ssh debian@192.168.1.100

# --- ここからは RISC-V 機器上で実行 ---

# システムディレクトリにインストール
sudo install -m 0755 /home/debian/nullclaw /usr/local/bin/nullclaw

# バージョン確認
nullclaw --version
# => nullclaw 2026.x.x  (riscv64-linux)
```

> **sudo が使えない場合**: `~/.local/bin/` にインストールして PATH を通してください。
> ```bash
> mkdir -p ~/.local/bin
> cp /home/debian/nullclaw ~/.local/bin/nullclaw
> echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
> source ~/.bashrc
> ```

---

## ステップ4 — Claude 認証キーを取得する

NullClaw は 2 種類の認証に対応しています。

### 方法 A: セットアップトークン（Claude Pro/Max サブスクリプション推奨）

API 課金なし、サブスクリプションをそのまま使えます。

**Claude Code がインストールされているマシンで**（NullClaw を動かすマシンとは別のターミナルで）実行:

```bash
claude setup-token
# => sk-ant-oat01-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx... という文字列が表示される
```

- `sk-ant-oat01-` で始まるトークンです
- このトークンを NullClaw の `api_key` フィールドに設定します
- NullClaw が `sk-ant-oat01-` を見て OAuth 認証を自動判別します

### 方法 B: 通常の API キー

[Anthropic Console](https://console.anthropic.com/) で発行する `sk-ant-api...` 形式のキーです。API 使用量に応じて課金されます。

---

## ステップ5 — Discord Bot を作成する

### 5-1. アプリケーションを作成する

1. [Discord Developer Portal](https://discord.com/developers/applications) を開く
2. **New Application** をクリック
3. アプリ名を入力（例: `smi-bot`）→ **Create**

### 5-2. Bot を追加してトークンを取得する

1. 左メニューの **Bot** をクリック
2. **Add Bot** → **Yes, do it!**
3. **Token** セクションの **Reset Token** をクリック → トークンをコピー

> Bot トークンの形式: `MTxxxxxxxxxxxxxxxx.Gxxxxx.xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`
> このトークンは一度しか表示されません。必ずコピーしてください。

### 5-3. 特権インテントを有効化する（必須）

**Bot** ページで以下を **ON** にします:

- ✅ **SERVER MEMBERS INTENT**
- ✅ **MESSAGE CONTENT INTENT** ← **これがないとメッセージ本文が読めません**

有効化しないと Bot がメッセージを受信しても内容が空になります。

### 5-4. Bot をサーバーに招待する

1. 左メニューの **OAuth2** → **URL Generator**
2. **Scopes** で `bot` にチェック
3. **Bot Permissions** で以下を選択:
   - `View Channels`
   - `Read Message History`
   - `Send Messages`
4. 生成された URL をブラウザで開いてサーバーに招待

---

## ステップ6 — NullClaw を設定する

**RISC-V 機器上で実行します。**

```bash
mkdir -p ~/.nullclaw
```

以下の内容で `~/.nullclaw/config.json` を作成します:

```json
{
  "default_provider": "anthropic",
  "default_temperature": 0.7,
  "models": {
    "providers": {
      "anthropic": {
        "api_key": "sk-ant-oat01-xxxxxxxxxxxxxxxx",
        "base_url": "https://api.anthropic.com"
      }
    }
  },
  "agents": {
    "defaults": {
      "model": {
        "primary": "claude-sonnet-4-6"
      }
    }
  },
  "channels": {
    "discord": {
      "accounts": {
        "main": {
          "token": "MTxxxxxxxxxxxxxxxx.Gxxxxx.xxxxxxxxxxxxxxxxxxxxxxx",
          "mention_only": false
        }
      }
    }
  }
}
```

### 設定値の説明

| フィールド | 説明 |
|-----------|------|
| `models.providers.anthropic.api_key` | ステップ4で取得した Claude API キー |
| `agents.defaults.model.primary` | 使用するモデル名。**`anthropic/` プレフィックスは不要**（つけると API エラー） |
| `channels.discord.accounts.main.token` | ステップ5で取得した Discord Bot トークン |
| `mention_only` | `false` = 全メッセージに応答、`true` = @メンション時のみ応答 |

### オプション設定

```json
{
  "channels": {
    "discord": {
      "accounts": {
        "main": {
          "token": "...",
          "mention_only": true,
          "guild_id": "123456789012345678",
          "allow_from": ["111111111111111111", "222222222222222222"]
        }
      }
    }
  }
}
```

| オプション | 説明 |
|-----------|------|
| `guild_id` | このサーバー ID のメッセージのみ処理（省略すると全サーバー対応） |
| `allow_from` | 応答するユーザー ID のリスト（省略すると全ユーザー対応） |

> **ユーザー ID の確認方法**: Discord の設定 → 詳細設定 → 開発者モードを ON → ユーザーを右クリック → 「ユーザー ID をコピー」

### 設定を確認する

```bash
nullclaw doctor
# => [ok] API key configured
# => [ok] default model: claude-sonnet-4-6
# => [ok] discord: token configured
```

---

## ステップ7 — 動作確認

### CLI でまず確認する

```bash
nullclaw agent -m "こんにちは"
# Sending to anthropic...
# こんにちは！何かお手伝いできることはありますか？
```

`error: CredentialsNotSet` が出る場合は config.json の `api_key` を確認してください。

### デーモンを手動で起動して Discord に繋げる

```bash
nullclaw daemon
# nullclaw daemon started
#   Components: 3 active
# info(daemon): Discord gateway thread started
# info(discord): Discord READY: session_id=xxxxxxxx...
```

`Discord READY` が表示されれば接続成功です。

### Discord でテストする

Bot が入っているサーバーのチャンネルでメッセージを送ります。
`mention_only: false` の場合はメンションなしでも応答します。

```
あなた:  こんにちは！
smi-bot: こんにちは！何かお手伝いできることはありますか？
```

---

## ステップ8 — systemd サービスとして常駐させる

手動で起動する代わりに、systemd で自動起動・自動再起動させます。

```bash
# サービスファイルのディレクトリを作成
mkdir -p ~/.config/systemd/user/

# NullClaw のサービスインストールコマンドで自動生成
nullclaw service install

# systemd にサービスを認識させる
systemctl --user daemon-reload

# 起動時に自動起動するよう有効化 + 今すぐ起動
systemctl --user enable --now nullclaw.service

# 状態確認
systemctl --user status nullclaw.service
```

```
● nullclaw.service - nullclaw daemon
     Loaded: loaded (/home/debian/.config/systemd/user/nullclaw.service; enabled)
     Active: active (running) since ...
```

### ログの確認

```bash
# リアルタイムで確認
journalctl --user -u nullclaw.service -f

# 期待するログ:
# info(daemon): Discord gateway thread started
# info(discord): Discord READY: session_id=...
```

### サービス管理コマンド

```bash
systemctl --user start nullclaw.service    # 起動
systemctl --user stop nullclaw.service     # 停止
systemctl --user restart nullclaw.service  # 再起動
systemctl --user status nullclaw.service   # 状態確認
```

---

## トラブルシューティング

### `Discord READY` が出ずに `ConnectionClosed` が繰り返される

このフォークで修正済みのはずですが、古いバイナリを使っている場合に発生します。`discord-daemon-integration` ブランチのコードを使っているか確認してください。

```bash
git branch  # => * discord-daemon-integration になっているか確認
```

### `no API key in providers config`

config.json の構造が間違っています。`providers` は必ず `models.providers` の下に入れてください。

```json
✅ 正しい:
{
  "models": {
    "providers": {
      "anthropic": { "api_key": "sk-ant-..." }
    }
  }
}

❌ 間違い:
{
  "providers": {
    "anthropic": { "api_key": "sk-ant-..." }
  }
}
```

### `model: anthropic/claude-sonnet-4-6` でエラー

Anthropic API に直接繋ぐ場合、モデル名にプロバイダープレフィックスを含めてはいけません。

```json
✅  "primary": "claude-sonnet-4-6"
❌  "primary": "anthropic/claude-sonnet-4-6"
```

### メッセージを送っても Bot が応答しない

**原因1: Message Content Intent が無効**
Discord Developer Portal → Bot → **MESSAGE CONTENT INTENT** を ON にしてください。

**原因2: Bot のパーミッション不足**
Bot を招待するとき `Send Messages` と `Read Message History` にチェックが入っているか確認してください。

**原因3: `mention_only: true` になっている**
`mention_only: false` にすると @メンションなしでも応答します。

**原因4: `allow_from` で自分のユーザー ID が除外されている**
`allow_from` を省略すると全ユーザーが対象になります。

### ビルドエラー（Zig バージョン不一致）

このリポジトリは **Zig 0.15.2** が必要です。

```bash
zig version  # => 0.15.2 であることを確認
```

`posix.close() catch {}` のエラーや `Io.Reader.read` が見つからないエラーが出る場合は、Zig のバージョンが古いです。

### RISC-V 機器に sudo がない / パスワードが要求される

sudo を使わずにインストールするには `~/.local/bin/` を使います。

```bash
mkdir -p ~/.local/bin
cp nullclaw ~/.local/bin/
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
```

サービスファイル `~/.config/systemd/user/nullclaw.service` の `ExecStart` も合わせて変更してください:

```ini
ExecStart=/home/debian/.local/bin/nullclaw daemon
```

---

## アーキテクチャ

```
Discord WebSocket Gateway
        │
        │ (TLS/WSS: gateway.discord.gg:443)
        ▼
  DiscordChannel.gatewayLoop()       ← 常駐スレッド、再接続ループ付き
        │
        │ op=0 MESSAGE_CREATE イベント受信
        ▼
  handleMessageCreate()
        │ フィルタ: bot除外 / mention_only / allow_from
        ▼
  bus.publishInbound(Message)        ← event bus への書き込み
        │
        ▼
  runDiscordLoop()                   ← 別スレッドで event bus を監視
        │
        │ consumeInbound()
        ▼
  SessionManager.processMessage()    ← セッションごとの会話履歴管理
        │
        │ HTTP POST /v1/messages
        ▼
  Anthropic Claude API
        │
        │ 応答テキスト
        ▼
  DiscordChannel.sendMessage()       ← REST API で送信
        │
        │ POST /api/v10/channels/{id}/messages
        ▼
Discord チャンネルに返信
```

### ハートビート

Discord ゲートウェイは接続維持のため定期的なハートビート（op=1）を要求します。
NullClaw は HELLO（op=10）で受け取った `heartbeat_interval`（通常 41250ms）に従い、専用スレッドで自動的に送信します。

---

## テスト済み環境

- **ハードウェア**: Milk-V Duo 256M（RISC-V 64bit, 256MB RAM）
- **OS**: Debian 13 (trixie)
- **Zig**: 0.15.2（x86_64 Linux でクロスコンパイル）
- **バイナリ**: 約 1.9 MB、完全静的リンク

---

## GitHub へのフォークとプッシュ

1. GitHub で `nullclaw/nullclaw` をフォーク
2. リモートを追加してプッシュ:

```bash
# YOUR_GITHUB_USERNAME を自分のユーザー名に変更
git remote add myfork https://github.com/YOUR_GITHUB_USERNAME/nullclaw.git
git push myfork discord-daemon-integration
```

3. GitHub 上で `discord-daemon-integration` ブランチから PR を作成（または公開）
