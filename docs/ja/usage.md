# 使い方と運用

このページでは、日常的なコマンド、サービスモード、トラブルシューティングを中心に説明します。

## このページのガイド

**このページの対象読者**

- CLI またはサービスモードで NullClaw を日常的に動かしているユーザー
- ヘルスチェック、再起動、変更後の検証手順を確認するオペレーター
- 起動、モデル、チャンネル、ゲートウェイに関するよくある問題の原因を絞り込むトラブルシューター

**次に読むページ**

- ここで紹介するよく使う手順以外も含む、より詳しい CLI リファレンスが必要な場合は[コマンド](./commands.md)を開いてください
- ゲートウェイを公開したり、許可リストや自律性の範囲を広げたりする前に[セキュリティ](./security.md)を開いてください
- 運用フローがペアリングや Webhook 呼び出しに依存している場合は[Gateway API](./gateway-api.md)を開いてください

**以下のページから来た場合**

- [インストール](./installation.md): このページは、バイナリがインストールされ、初回実行時のチェックを行える状態になったところから続きます
- [設定](./configuration.md): 設定の変更を実行時のコマンドやトラブルシューティング手順で検証するには、ここに来てください
- [コマンド](./commands.md): 単なるコマンド一覧ではなく、運用上の手順の流れが知りたい場合はここに戻ってきてください

## 初回実行の流れ

1. 初期化します:

```bash
nullclaw onboard --interactive
```

2. テストメッセージを送信します:

```bash
nullclaw agent -m "hello nullclaw"
```

3. 常駐型のゲートウェイを起動します:

```bash
nullclaw gateway
```

## コマンドクイックリファレンス

| コマンド | 用途 |
|---|---|
| `nullclaw onboard --api-key sk-... --provider openrouter` | プロバイダーと API キーのクイックセットアップ |
| `nullclaw onboard --interactive` | 対話形式のフルセットアップ |
| `nullclaw onboard --channels-only` | チャンネルと許可リストのみを再設定 |
| `nullclaw agent -m "..."` | 単一メッセージモード |
| `nullclaw agent` | 対話モード |
| `nullclaw gateway` | 常駐型ランタイムを起動(デフォルトは `127.0.0.1:3000`) |
| `nullclaw service install` | バックグラウンドサービスをインストール |
| `nullclaw service start` | バックグラウンドサービスを開始 |
| `nullclaw service status` | サービスの状態を確認 |
| `nullclaw service stop` | バックグラウンドサービスを停止 |
| `nullclaw service uninstall` | バックグラウンドサービスをアンインストール |
| `nullclaw doctor` | 診断を実行 |
| `nullclaw status` | 全体の状態を表示 |
| `nullclaw channel status` | チャンネルのヘルス状態を表示 |
| `nullclaw channel start telegram` | 特定のチャンネルを開始 |
| `nullclaw migrate openclaw --dry-run` | OpenClaw からの移行をドライラン |
| `nullclaw migrate openclaw` | OpenClaw からの移行を実行 |
| `nullclaw history list [--limit N] [--offset N] [--json]` | 会話セッションを一覧表示 |
| `nullclaw history show <session_id> [--limit N] [--offset N] [--json]` | セッションのメッセージを表示 |

## サービスモードの推奨事項

常駐型のデプロイの場合:

- macOS では `launchctl` を使用します。
- Linux では、利用可能であれば `systemd --user` を使用し、必要なランタイムが存在する場合は OpenRC または SysVinit にフォールバックします。
- Windows では Service Control Manager を使用します。
- Linux で、動作する `systemd --user` も必要な OpenRC/SysVinit サポートもない場合、service サブコマンドは失敗します。代わりにフォアグラウンドでの `nullclaw gateway` か、別のスーパーバイザーを使用してください。

```bash
nullclaw service install
nullclaw service start
nullclaw service status
```

高度なシークレットの受け渡し:

- 生成されたサービスランチャーは、`nullclaw gateway` を起動する前に、実行可能な `~/.nullclaw/service-env` ヘルパーがあるかどうかも確認します。
- このヘルパーを使うと、インストール済みのサービスユニットやスクリプトを編集することなく、`dotenvx`、`sops`、またはその他のローカルのシークレットローダーからシークレットを注入できます。

大きな設定変更を行った後は、サービスを再起動してください:

```bash
nullclaw service stop
nullclaw service start
```

## ゲートウェイとペアリング

- デフォルトのゲートウェイ: `127.0.0.1:3000`
- 推奨: `gateway.require_pairing = true` のままにしておく
- 外部に公開する場合は、パブリックアドレスへの直接バインドよりもトンネルやリバースプロキシを優先する
- `/pair` は POST 専用で、`X-Pairing-Code` を使用します。無効な試行が繰り返されると、レート制限や一時的なロックがかかる場合があります

ヘルスチェック:

```bash
curl http://127.0.0.1:3000/health
```

## FAQ

### 1) 設定エラーで起動に失敗する

手順:

1. `nullclaw doctor` を実行して、正確なエラーの詳細を確認します。
2. キー名やネスト構造を `config.example.json` と比較します。
3. JSON の構文(カンマ、引用符、波かっこ)を検証します。

### 2) モデルの呼び出しが失敗する(401/403)

よくある原因:

- API キーが無効、または期限切れになっている。
- プロバイダーが一致していない(例: 選択したプロバイダーに対して誤ったキーを使っている)。
- モデルのルート形式や文字列が無効である。

確認:

```bash
nullclaw status
```

その後、オンボーディングをやり直します:

```bash
nullclaw onboard --interactive
```

### 3) チャンネルがメッセージを受信しない

確認事項:

- `channels.<name>.accounts.*` のトークン、Webhook、アカウントの設定。
- チャンネル固有の許可リストやゲーティングの不一致(`allow_from`、`group_allow_from`、`require_mention` などの設定)。空の `allow_from` は、すべてを拒否するスイッチではありません。
- `nullclaw channel status` のヘルス出力。
- DingTalk 固有のストリームや返信先のチェックについては、
  [DingTalk 運用準備](./ops/dingtalk-ops-readiness.md)を開いてください。

### 4) ゲートウェイは起動するが外部から到達できない

よくある原因:

- まだ `127.0.0.1` にバインドされている。
- トンネルやリバースプロキシが設定されていない。
- ファイアウォールのポートが開放されていない。

### 5) プロバイダーが 429 / "rate limit exceeded" を返す

よくある原因:

- 低クォータのコーディングプランでは、通常のチャットは動作していても、ツールを多用するエージェントのターンが拒否される場合がある。
- 現在のプロバイダープランに対して、リトライの負荷が過剰になっている。
- プライマリのプロバイダーがクォータやレート制限に達したときのフォールバックが設定されていない。

確認:

- フォアグラウンドで実行する場合は、まず `nullclaw agent --verbose` から始めてください。
- サービスモードの場合は、`~/.nullclaw/logs/daemon.stdout.log` と `~/.nullclaw/logs/daemon.stderr.log` を確認してください。
- `nullclaw status` を実行して、現在のプロバイダーとモデルの組み合わせを確認してください。

プランは有効だが不安定な場合は、信頼性に関する設定を控えめに調整してください:

```json
{
  "reliability": {
    "provider_retries": 1,
    "provider_backoff_ms": 3000,
    "fallback_providers": ["openrouter"]
  }
}
```

同じプロバイダーのキーを複数持っている場合は、`reliability.api_keys` を追加すると NullClaw がキーをローテーションできるようになります。

### 6) ローカルの Ollama モデルが `scheduler_tool` にアクセスできないと言う

通常、これが意味すること:

- NullClaw における正式なツール名は `schedule` です。
- ローカルの Ollama で提供される一部のモデルは、代わりに `scheduler_tool` や `schedule_tool` を出力します。
- 現在の NullClaw ビルドでは、ディスパッチ前にこれらの Ollama のエイリアスを `schedule` に正規化します。

確認:

- Ollama のツールエイリアス正規化の修正を含むビルドを実行していることを確認してください。
- スケジューラー関連の名前で依然として `Unknown tool` が表示される場合は、`nullclaw agent --verbose` で再実行してください。
- 古いバイナリに固定している場合は、スケジューラーの設定を変更する前にアップグレードしてください。この問題の原因は通常ツール名のずれであり、スケジューラーが無効になっているわけではありません。

## 変更後のチェックリスト

設定を編集した後:

```bash
nullclaw doctor
nullclaw status
nullclaw channel status
nullclaw agent -m "self-check"
```

ゲートウェイを使うシナリオの場合:

```bash
nullclaw gateway
curl http://127.0.0.1:3000/health
```

## 次のステップ

- あまり使われない CLI フローや、より幅広いコマンドの一覧については[コマンド](./commands.md)を開いてください
- ローカル限定の運用からより広い範囲への公開に移る前に、[セキュリティ](./security.md)を確認してください
- 運用チェックにペアリングや Webhook 連携が含まれる場合は、[Gateway API](./gateway-api.md)を利用してください

## 関連ページ

- [インストール](./installation.md)
- [設定](./configuration.md)
- [コマンド](./commands.md)
- [セキュリティ](./security.md)
