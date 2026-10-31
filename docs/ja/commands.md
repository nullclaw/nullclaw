# コマンド

このページでは NullClaw の CLI をタスク別にまとめているため、ヘルプ出力全体に目を通さなくても適切なコマンドをすばやく見つけられます。

`nullclaw help` はトップレベルの概要を表示します。このページはその内容に沿いつつ、詳細なサブコマンドと注意事項まで掘り下げて説明します。

## ページガイド

**このページの対象読者**

- NullClaw をすでにインストールしていて、適切な CLI のエントリポイントを知りたいユーザー
- ランタイム、サービス、チャンネル、診断のコマンドを確認する運用担当者
- コマンド名、フラグ、タスクのグループ分けを検証するコントリビューター

**次に読むページ**

- コマンドが何に対して作用するのかを理解したい場合は、[設定](./configuration.md) を開いてください
- コマンドの一覧ではなくワークフローを知りたい場合は、[使い方と運用](./usage.md) を開いてください
- CLI の動作やドキュメントを変更する場合は、[開発](./development.md) を開いてください

**以下のページから来た場合**

- [README](./README.md): このページは、具体的なコマンドを見つけるための最短ルートです
- [インストール](./installation.md): セットアップ後は、このページでインストールを検証し、日常的に使うコマンドを覚えてください
- `nullclaw help`: 組み込みのヘルプは正しいものの簡潔すぎる場合に、このページを使ってください

## まずはここから

- ヘルプを表示: `nullclaw help`
- バージョンを表示: `nullclaw version` または `nullclaw --version`
- 初回セットアップ: `nullclaw onboard --interactive`
- 簡易的な動作確認: `nullclaw agent -m "hello"`
- 常駐モード: `nullclaw gateway`

## セットアップと対話

| コマンド | 用途 |
|---|---|
| `nullclaw help` | トップレベルのヘルプを表示します |
| `nullclaw version` / `nullclaw --version` | CLI のバージョンを表示します |
| `nullclaw onboard --interactive` | 対話型のセットアップウィザードを実行します |
| `nullclaw onboard --api-key sk-... --provider openrouter` | プロバイダーと API キーをすばやく設定します |
| `nullclaw onboard --api-key ... --provider ... --model ... --memory ...` | プロバイダー、モデル、メモリバックエンドを 1 つのコマンドで設定します |
| `nullclaw onboard --channels-only` | チャンネルと許可リストのみを再設定します |
| `nullclaw agent -m "..."` | 単一のプロンプトを実行します |
| `nullclaw agent --workspace /path/to/workspace -m "..."` | このプロセスに限り、特定のワークスペースを対象にエージェントを実行します |
| `nullclaw agent --skill news-digest -m "..."` | 指定したスキルを有効にして単一のプロンプトを実行します |
| `nullclaw agent` | 対話型のチャットモードを開始します |
| `nullclaw acp` | ACP 互換エディター向けに Agent Client Protocol の stdio アダプターを実行します |
| `nullclaw acp --provider openai --model gpt-5.2` | エディターから起動されるセッション向けに、ACP アダプターをプロバイダー/モデルに固定します |

### 対話中のモデルルーティング

- `nullclaw agent` では、`/model` で現在のモデルと、設定されたルーティング/フォールバックの状態を表示します。
- `/config reload` は、`config.json` のうちサポートされているキー（エージェントプロファイルを含む）をホットリロードします。
- 自動ルーティングが設定されている場合、`/model` は直近の自動ルーティングの判断とその理由も表示します。
- ルーティング先のプロバイダーが一時的にレート制限を受けているかクレジットを使い切っている場合、`/model` はクールダウンが終わるまでそのルートを縮退状態として表示します。
- `/model` は、設定済みの自動ルートを `cost_class` と `quota_class` のメタデータとともに一覧表示します。
- `/model <provider/model>` は、現在のセッションをそのモデルに固定し、自動ルーティングを無効にします。
- `/model auto` はユーザーによる固定を解除し、設定済みのデフォルトモデルに戻して、同じセッション内の以降のターンで `model_routes` を再び有効にします。
- `model_routes` が設定されていない場合でも、`/model auto` は固定を解除し、セッションを設定済みのデフォルトモデルに戻します。
- `--model` または `--provider` を付けて `nullclaw agent` を起動した場合も、その実行は固定され、`model_routes` はバイパスされます。
- `--skill <name>` を付けて `nullclaw agent` を起動すると、最初のメッセージまたは REPL のターンの前にそのスキルが有効になります。
- `nullclaw acp` は、stdio 上で改行区切りの JSON-RPC を話します。エディターは絶対パスの `cwd` を指定して ACP セッションを作成し、NullClaw はその cwd を `agent invoke` のワークスペースとして引き渡します。

## ランタイムと運用

| コマンド | 用途 |
|---|---|
| `nullclaw gateway` | 設定されたホストとポートで常駐ランタイムを起動します |
| `nullclaw gateway --port 8080` | CLI からゲートウェイのポートを上書きします |
| `nullclaw gateway --host 0.0.0.0 --port 8080` | CLI からホストとポートを上書きします |
| `nullclaw gateway --workspace /path/to/workspace` | このゲートウェイプロセスのワークスペースディレクトリを上書きします |
| `nullclaw service install` | バックグラウンドサービスをインストールします |
| `nullclaw service start` | バックグラウンドサービスを開始します |
| `nullclaw service stop` | バックグラウンドサービスを停止します |
| `nullclaw service restart` | バックグラウンドサービスを再起動します |
| `nullclaw service status` | サービスの状態を表示します |
| `nullclaw service uninstall` | バックグラウンドサービスを削除します |
| `nullclaw status [--json]` | システム全体の状態を表示するか、機械可読なランタイムのスナップショットを出力します |
| `nullclaw doctor` | 診断を実行します |
| `nullclaw update --check` | インストールせずにアップデートを確認します |
| `nullclaw update --yes` | 確認なしでアップデートをインストールします |
| `nullclaw auth login openai-codex` | OAuth デバイスフローで `openai-codex` を認証します |
| `nullclaw auth login openai-codex --import-codex` | `~/.codex/auth.json` から認証情報をインポートします |
| `nullclaw auth status openai-codex` | 認証状態を表示します |
| `nullclaw auth logout openai-codex` | 保存されている認証情報を削除します |

注意事項:

- `auth` は現在 `openai-codex` のみをサポートしています。
- `gateway --host/--port` が上書きするのはバインドの設定だけです。それ以外のゲートウェイのセキュリティ設定は引き続き設定ファイルから読み込まれます。
- `agent --workspace` と `gateway --workspace` は、現在のプロセスで解決されるワークスペースを上書きします。これは `NULLCLAW_WORKSPACE` を設定するのと同等です。

## チャンネル、スケジューリング、拡張機能

### `channel`

| コマンド | 用途 |
|---|---|
| `nullclaw channel list [--json]` | 既知のチャンネルと設定済みのチャンネルを一覧表示します |
| `nullclaw channel start` | 利用可能なデフォルトのチャンネルを開始します |
| `nullclaw channel start telegram` | 特定のチャンネルを開始します |
| `nullclaw channel status` | チャンネルの健全性を表示します |
| `nullclaw channel info <type> [--json]` | 1 つのチャンネルタイプについて、設定済みのアカウントを表示します |
| `nullclaw channel add <type>` | 設定にチャンネルを追加するための案内を表示します |
| `nullclaw channel remove <name>` | 設定からチャンネルを削除するための案内を表示します |

### `cron`

| コマンド | 用途 |
|---|---|
| `nullclaw cron list [--json]` | スケジュールされたタスクを一覧表示します |
| `nullclaw cron status [--json]` | スケジューラー全体の状態とジョブのカウンターを表示します |
| `nullclaw cron add "0 * * * *" "command"` | 定期的に実行するシェルタスクを追加します |
| `nullclaw cron add-agent "0 * * * *" "prompt" [--model <model>] [--session-target <isolated\|main>] [--announce] [--channel <name>] [--account <id>] [--to <id>]` | 定期的に実行するエージェントタスクを追加します |
| `nullclaw cron once 10m "command"` | 遅延実行する 1 回限りのシェルタスクを追加します |
| `nullclaw cron once-agent 10m "prompt" [--model <model>] [--session-target <isolated\|main>] [--announce] [--channel <name>] [--account <id>] [--to <id>]` | 遅延実行する 1 回限りのエージェントタスクを追加します |
| `nullclaw cron run <id>` | タスクを即座に実行します |
| `nullclaw cron pause <id>` / `resume <id>` | タスクを一時停止または再開します |
| `nullclaw cron remove <id>` | タスクを削除します |
| `nullclaw cron runs <id>` | 最近の実行履歴を表示します |
| `nullclaw cron update <id> --expression ... --command ... --prompt ... --model ... --enable/--disable` | 既存のタスクを更新します |

### `skills`

| コマンド | 用途 |
|---|---|
| `nullclaw skills list` | インストール済みのスキルを一覧表示します |
| `nullclaw skills install <source>` | Git の URL、ローカルパス、または HTTPS の well-known スキルエンドポイントからインストールします |
| `nullclaw skills install --name <query>` | スキルレジストリを検索し、最も一致するスキルをインストールします |
| `nullclaw skills remove <name>` | スキルを削除します |
| `nullclaw skills info <name>` | スキルのメタデータを表示します |

### `history`

| コマンド | 用途 |
|---|---|
| `nullclaw history list [--limit N] [--offset N] [--json]` | 会話セッションを一覧表示します |
| `nullclaw history show <session_id> [--limit N] [--offset N] [--json]` | セッションのメッセージを表示します |

## データ、モデル、ワークスペース

### `memory`

| コマンド | 用途 |
|---|---|
| `nullclaw memory stats` | 解決済みのメモリ設定とカウンターを表示します |
| `nullclaw memory count` | メモリエントリの総数を表示します |
| `nullclaw memory reindex` | ベクトルインデックスを再構築します |
| `nullclaw memory search "query" --limit 10` | メモリに対して検索を実行します |
| `nullclaw memory get <key>` | メモリエントリを 1 件表示します |
| `nullclaw memory list --category task --limit 20` | カテゴリ別にメモリエントリを一覧表示します |
| `nullclaw memory export-jsonl --limit 1000` | メモリから、管理された PII 秘匿化済みの JSONL データセットをエクスポートします |
| `nullclaw memory hygiene-report --json` | メモリの完全一致/正規化後の重複レポートをドライランで作成します |
| `nullclaw memory drain-outbox` | 永続的なベクトルのアウトボックスキューを処理して空にします |
| `nullclaw memory forget <key>` | メモリエントリを 1 件削除します |

`memory export-jsonl` は、1 行につき 1 つの JSON オブジェクトを、安定した
`schema_version`、`key`、`category`、`timestamp`、`session_id`、`content` の
スキーマで出力します。`--include-internal` を指定しない限り、bootstrap/autosave の内部エントリは
除外されます。DS ノートブック、モデルの
評価、外部レビュー向けに、コンテンツはデフォルトで PII が秘匿化されます。`--include-pii` は、信頼できるローカルで生データを
エクスポートする場合にのみ使用してください。

`memory hygiene-report` は非破壊的です。選択したメモリの範囲をスキャンし、
完全一致の重複に加えて、大文字・小文字や空白の違いを除けば一致する正規化後の重複を
報告します。エントリの削除や書き換えは行いません。

### `workspace`、`capabilities`、`models`、`migrate`

| コマンド | 用途 |
|---|---|
| `nullclaw workspace edit AGENTS.md` | ブートストラップ用の Markdown ファイルを `$EDITOR` で開きます |
| `nullclaw workspace reset-md --dry-run` | ワークスペースの Markdown のリセット内容をプレビューします |
| `nullclaw workspace reset-md --include-bootstrap --clear-memory-md` | 同梱の Markdown ファイルをリセットし、必要に応じて追加のファイルも消去します |
| `nullclaw workspace audit` | ワークスペースのファイルをスキャンし、シークレット漏えいの可能性（トークンプレフィックス、PEM ブロック、URL 内の認証情報、高エントロピーな文字列）を検出します |
| `nullclaw workspace audit --staged \| --commit <sha> \| --range a..b` | ワークスペースのツリーの代わりに、ステージされた差分、過去のコミット、または git のリビジョン範囲を監査します |
| `nullclaw workspace audit --json [--only-secrets] [--fail-on <level>]` | CI 連携向けの機械可読な出力です。検出結果がしきい値に達すると 0 以外の終了コードを返します |
| `nullclaw workspace audit --llm-triage external` | `workspace_audit.llm_triage` または設定済みのプライマリ LLM プロバイダーを使い、プライバシーを保護したエンベロープで検出結果を再分類します（生のシークレット値はマシンの外に出ません） |
| `nullclaw workspace audit --llm-provider ollama --llm-model qwen2.5-coder:7b --llm-max-calls 20` | 1 回の実行に限り、設定済みの監査トリアージのプロバイダー、モデル、外部呼び出しの上限回数を上書きします |
| `nullclaw workspace audit --llm-triage dry-run` | LLM を呼び出さずに、送信されるはずのエンベロープを表示します |
| `nullclaw capabilities` | 機能の概要をテキストで表示します |
| `nullclaw capabilities --json` | 機能のマニフェストを JSON で表示します |
| `nullclaw config show [--json]` | ディスク上の設定全体を表示します |
| `nullclaw config get <path> [--json]` | ドット区切りで指定した設定値を 1 つディスクから読み取ります |
| `nullclaw models list` | プロバイダーとデフォルトモデルを一覧表示します |
| `nullclaw models info <model>` | モデルの詳細を表示します |
| `nullclaw models summary [--json]` | 連携機能が使用する、プロバイダー/キーを安全に扱った管理用サマリーを表示します |
| `nullclaw models benchmark` | モデルのレイテンシベンチマークを実行します |
| `nullclaw models refresh` | モデルカタログを更新します |
| `nullclaw migrate openclaw --dry-run` | OpenClaw からの移行内容をプレビューします |
| `nullclaw migrate openclaw --source /path/to/workspace` | 特定の移行元ワークスペースから移行します |

注意事項:

- `workspace edit` は、`markdown` や `hybrid` などのファイルベースのバックエンドでのみ動作します。
- ブートストラップのデータがデータベースのバックエンドに保存されている場合、CLI は代わりにエージェントの `memory_store` ツールを使うよう案内します。
- `--json` 付きの読み取り系コマンドは、自動化と、NullHub のマネージドインスタンス管理 API の境界での利用を想定しています。

## ハードウェアと自動化向けのエントリポイント

### `hardware`

| コマンド | 用途 |
|---|---|
| `nullclaw hardware scan` | 接続されているハードウェアをスキャンします |
| `nullclaw hardware flash <firmware_file> [--target <board>]` | デバイスにファームウェアを書き込みます（現在はプレースホルダーのコマンドです） |
| `nullclaw hardware monitor` | ハードウェアデバイスを監視します（現在はプレースホルダーのコマンドです） |

### 機械向けのトップレベルフラグ

これらは、日常的な CLI の利用よりも、自動化、プローブ、連携の用途で役立ちます:

| コマンド | 用途 |
|---|---|
| `nullclaw --export-manifest` | ランタイムのマニフェストをエクスポートします |
| `nullclaw --list-models --provider <name> [--api-key <key>] [--base-url <url>]` | カスタムの OpenAI 互換エンドポイントを含め、モデル情報を表示します |
| `nullclaw --probe-provider-health` | プロバイダーの健全性をプローブします |
| `nullclaw --probe-channel-health` | チャンネルの健全性をプローブします |
| `nullclaw --from-json` | JSON 駆動のエントリパスを実行します |

## 推奨されるトラブルシューティングの順序

1. `nullclaw doctor`
2. `nullclaw status`
3. `nullclaw channel status`
4. `nullclaw agent -m "self-check"`
5. ゲートウェイが関係している場合は、`curl http://127.0.0.1:3000/health` も実行してください

## 次のステップ

- タスク別のランタイムのワークフローについては、[使い方と運用](./usage.md) に進んでください
- コマンドがプロバイダー、ゲートウェイ、メモリの設定に依存する場合は、[設定](./configuration.md) に進んでください
- コマンドの動作を変更したり、コードと合わせてドキュメントを更新したりする予定がある場合は、[開発](./development.md) に進んでください

## 関連ページ

- [README](./README.md)
- [インストール](./installation.md)
- [Gateway API](./gateway-api.md)
- [アーキテクチャ](./architecture.md)
