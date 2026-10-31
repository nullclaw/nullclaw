# 設定

NullClaw は OpenClaw の設定構造と互換性があり、`snake_case` のキーを使用します。

## ページガイド

**このページの対象読者**

- メインの `config.json` を作成・編集するユーザー
- チャンネル、ゲートウェイの動作、自律性の制限を調整するオペレーター
- 既存の OpenClaw 形式の設定を NullClaw に移行するユーザー

**次に読むページ**

- 設定を編集したら、[使い方と運用](./usage.md) を開いてランタイムの動作を検証してください
- 権限、公開範囲、ツールのスコープを広げる前に [セキュリティ](./security.md) を開いてください
- 設定変更がペアリング、Webhook、外部連携に影響する場合は [Gateway API](./gateway-api.md) を開いてください
- コア以外のチャンネルを接続する場合は [外部チャンネルプラグイン](./external-channels.md) を開いてください

**以下のページから来た場合**

- [インストール](./installation.md): `nullclaw` がインストールされ、初回セットアップの準備が整ったら、このページに進みます
- [README](./README.md): オペレーター/ユーザー向けドキュメントのルートを選んだ後の、詳細な設定ガイドです
- [Gateway API](./gateway-api.md): API のワークフローが具体的な `gateway` やチャンネルの設定に依存する場合は、このページに戻ってきてください

## 設定ファイルのパス

- macOS/Linux: `~/.nullclaw/config.json`
- Windows: `%USERPROFILE%\\.nullclaw\\config.json`

推奨される最初のステップ:

```bash
nullclaw onboard --interactive
```

これにより初期設定ファイルが生成されます。

## 最小限の動作する設定

以下の例でローカル CLI モードを実行できます(API キーは置き換えてください):

```json
{
  "models": {
    "providers": {
      "openrouter": {
        "api_key": "YOUR_OPENROUTER_API_KEY"
      }
    }
  },
  "agents": {
    "defaults": {
      "model": {
        "primary": "openrouter/anthropic/claude-sonnet-4"
      }
    }
  },
  "channels": {
    "cli": true
  },
  "memory": {
    "backend": "sqlite",
    "auto_save": true
  },
  "gateway": {
    "host": "127.0.0.1",
    "port": 3000,
    "require_pairing": true
  },
  "autonomy": {
    "level": "supervised",
    "workspace_only": true,
    "max_actions_per_hour": 20
  },
  "security": {
    "sandbox": {
      "backend": "auto"
    },
    "audit": {
      "enabled": true
    }
  }
}
```

## コアセクション

### `diagnostics`

- ランタイムの診断とオブザーバビリティの出力を制御します。
- OpenTelemetry には、ネストされた `diagnostics.otel` オブジェクトを使用します。
- OTEL のスパンは、ターンの完了やエージェントのシャットダウンといったランタイムの自然な区切りでフラッシュされます。長時間実行されるフローでは、フォールバックとしてバッチフラッシュも引き続き使用されます。
- リモートのコレクターに対しては、`diagnostics.otel.endpoint` に `https://...` を使用してください。プレーンな `http://...` は、localhost/プライベートなコレクター、または `host.docker.internal`、`host.containers.internal`、`otel` のような単一ラベルのサービス名といったコンテナローカルのターゲットに対してのみ受け付けられます。

ロギングフラグ(すべてデフォルトは `false`)。`info` レベルの行は stderr に出力されます。つまり、`nullclaw agent` や `nullclaw gateway` をフォアグラウンドで実行している場合はターミナルに表示されます。これらをファイルに保存するかどうかはサービスラッパーや独自のリダイレクト次第です。サービスモードでは `~/.nullclaw/logs/daemon.stderr.log` に書き込まれます(launchd のサービス設定が指定します)が、`gateway` コマンド自体はこれらをデーモンのログファイルに振り向けません:

- `log_tool_calls`: 各ツール呼び出しを名前、ステータス、所要時間とともにログに記録します。ツールの引数は `log_llm_io` も有効な場合にのみ含まれます。
- `log_message_receipts`: ユーザーメッセージを受信したことをログに記録します。メタデータ(チャンネル、セッションハッシュ、サイズ)のみで、内容は決して記録しません。
- `log_message_payloads`: ユーザーに見える受信/送信メッセージの内容プレビューをログに記録します。UTF-8 セーフで 4,096 バイトが上限となり、それより長い場合は `[log preview truncated]` と表示されます。ローカルでのデバッグ専用です。機密性の高いテキストが含まれる可能性があります。
- `log_llm_io`: チャット呼び出しの前後で、プロバイダーへのリクエスト/レスポンス内容の、秘匿化・切り詰めされたプレビューをログに記録します。レスポンスと推論のプレビューも含まれます。ローカルでのデバッグ専用です。機密性の高いテキストが含まれる可能性があるため、本番環境ではオフにしておいてください。
- `token_usage_ledger_enabled`(デフォルト `true`)と `token_usage_ledger_window_hours` / `token_usage_ledger_max_bytes` / `token_usage_ledger_max_lines`: レスポンスごとのトークンカウンターを、`config.json` の近くにある JSONL 台帳に永続化します。記録されるのはトークン数(provider/model/prompt/completion/total)のみで、メッセージのテキストは決して記録されません。

例(本番環境でも安全: 内容を含むフラグはオフ):

```json
{
  "diagnostics": {
    "backend": "otel",
    "log_tool_calls": true,
    "log_message_receipts": true,
    "log_message_payloads": false,
    "log_llm_io": false,
    "otel": {
      "endpoint": "https://otel.example.com:4318",
      "service_name": "nullclaw",
      "headers": {
        "Authorization": "Bearer example-token"
      }
    }
  }
}
```

### `models.providers`

- LLM プロバイダーの接続パラメーターと API キーを定義します。
- 一般的なプロバイダー: `openrouter`、`openai`、`anthropic`、`groq`、`nearai`、`atlas-cloud`、`evolink`、`edenai`。

例:

```json
{
  "models": {
    "providers": {
      "openrouter": { "api_key": "sk-or-..." },
      "nearai": { "api_key": "YOUR_NEARAI_API_KEY" },
      "atlas-cloud": { "api_key": "YOUR_ATLASCLOUD_API_KEY" },
      "edenai": { "api_key": "YOUR_EDENAI_API_KEY" },
      "evolink": { "api_key": "YOUR_EVOLINK_API_KEY" },
      "anthropic": { "api_key": "sk-ant-..." },
      "openai": { "api_key": "sk-..." }
    }
  }
}
```

プロバイダーごとの共通フィールド:

- `api_key`: そのプロバイダーエントリーの認証情報です。
- `base_url`: プロバイダー固有の API エンドポイントの上書きです。期待されるパスの形式は
  プロバイダーによって異なります。OpenAI 互換のプロバイダーは通常 `/v1`
  ベースを想定しますが、ネイティブの Anthropic プロバイダーはそうではありません。
- `api_mode`: 互換性のあるプロバイダーで `chat_completions` または `responses` を選択します。
- `user_agent`: オプションの `User-Agent` ヘッダーの上書きです。
- `max_streaming_prompt_bytes`: 推定プロンプトサイズがこの値を超える場合、ストリーミングをスキップします。
- `chat_template_enable_thinking_param`: カスタムの OpenAI 互換 vLLM/Qwen エンドポイント向けに、`reasoning_effort` を `chat_template_kwargs.enable_thinking` にマッピングします。

#### ネイティブ Anthropic プロバイダー

NullClaw には Anthropic API に直接接続する専用の Anthropic プロバイダーがあり、
OpenRouter やプロキシは不要です。

認証オプション:

- **Anthropic Console の API キー** は `x-api-key` ヘッダーで送信されます。キーを
  `models.providers.anthropic.api_key` に設定するか、`ANTHROPIC_API_KEY` を設定してください。
- `sk-ant-oat01-` で始まる **Claude サブスクリプションのセットアップトークン** は
  Bearer 認証で送信されます。`claude setup-token` で長期間有効なトークンを生成し、
  それを `models.providers.anthropic.api_key` に設定するか、
  `ANTHROPIC_OAUTH_TOKEN` を設定してください。NullClaw は Claude Code の認証情報ストアを読み取ったり、
  トークンをリフレッシュしたりしません。[Claude Code 認証ガイド](https://code.claude.com/docs/en/authentication#generate-a-long-lived-token) を参照してください。

このプロバイダーは、テキストのストリーミング、URL および base64 の画像入力、非ストリーミングリクエストでの
ネイティブなツール呼び出しをサポートしています。`reasoning_effort` を設定する(または
`/think` を使う)と、対応するモデルで Anthropic の拡張思考(extended thinking)が有効になります。
NullClaw は Claude Opus/Sonnet 4.6 ではアダプティブ思考を使用し、それより古い対応モデルでは
手動のバジェットを使用します。モデル固有の Anthropic の制限は引き続き適用されます。

例(Anthropic API キーを直接使用):

```json
{
  "models": {
    "providers": {
      "anthropic": { "api_key": "sk-ant-api03-..." }
    }
  },
  "agents": {
    "defaults": {
      "model": { "primary": "anthropic/claude-sonnet-4-6" }
    }
  }
}
```

注意事項:

- `agents.defaults.model.primary` では、Anthropic のモデル ID に
  `anthropic/` を前置します。例: `anthropic/claude-sonnet-4-6`。エージェントエントリーに
  別途 `"provider": "anthropic"` フィールドがある場合は、代わりにプレフィックスなしのモデル ID を使用してください。
  NullClaw のカタログに登録されている Anthropic のモデル ID は
  `nullclaw --list-models --provider anthropic` で参照できます。このコマンドは、
  お使いの Anthropic アカウントで有効なモデルを調べるものではありません。
- `base_url` フィールドはオプションで、デフォルトは `https://api.anthropic.com` です。
  Anthropic 互換のプロキシやゲートウェイを使う場合は、`/v1/messages` の手前の API ルートを設定してください
  (末尾の `/v1` は含めないでください)。NullClaw がそのパスを付加します。
  リモートのエンドポイントは HTTPS を使用する必要があります。プレーンな HTTP は、ローカルまたは
  プライベートネットワークのホストに対してのみ受け付けられます。

### `agents.defaults.model.primary`

- デフォルトのモデルルートを設定します。通常は `provider/vendor/model` の形式です。
- 例: `openrouter/anthropic/claude-sonnet-4`

### `agent.default_queue_mode`

- 新しく作成されるセッションの受信キューモードを設定します。指定できる値は `off`、`serial`、`latest`、`debounce` で、デフォルトは `off` です。
- `off` はターンの実行中に届いたメッセージを破棄し、`serial` はアクティブなターンの完了を待ち、`latest` は最新の保留中のインジェクションを保持します。`debounce` は既存のランタイムのデバウンスモードを選択します。このフィールドでは、その時間、上限、破棄ポリシーは設定しません。
- `/queue` で現在のセッションのモードを上書きできます。`/queue reset`、`/restart`、`/debug reset` で設定済みのデフォルトに戻ります。
- セッションマネージャーと新しく作成されるセッションが同じデフォルトを使用するように、変更を反映するには再起動が必要です。

例:

```json
{
  "agent": {
    "default_queue_mode": "latest"
  }
}
```

### `workspace_audit.llm_triage`

- `nullclaw workspace audit --llm-triage external` で使用するプロバイダー/モデルを選択します。
- これ自体では LLM トリアージは有効になりません。コマンドラインのモードは引き続きオプトインです。
- 省略した場合は `agents.defaults.model.primary` にフォールバックします。

例:

```json
{
  "workspace_audit": {
    "llm_triage": {
      "provider": "ollama",
      "model": "qwen2.5-coder:7b",
      "max_calls": 20
    }
  }
}
```

プロバイダーが `models.providers` に設定されている場合は、プロバイダーをプレフィックスにした参照としてモデルを指定することもできます。例: `"model": "openrouter/anthropic/claude-sonnet-4"`。

### `model_routes`

- `nullclaw agent` でターンごとにモデルを自動選択するための、オプションのトップレベルのルーティングテーブルです。
- 各エントリーは、ルートの `hint` を具体的な `provider` と `model` にマッピングします。
- 現在のデーモンで認識されるルーティングヒントは `fast`、`balanced`、`deep`、`reasoning`、`vision` です。
- `balanced` は設定されている場合の通常のフォールバックです。`fast` は、短いステータス/一覧/確認のプロンプトや、抽出、カウント、分類、結果だけを返す限定的な変換といった、その他の短い構造化タスクで優先されます。`deep` と `reasoning` は、調査、計画、トレードオフ分析、長いコンテキストで優先されます。`vision` は画像を含むターンで使用されます。
- `api_key` はオプションです。省略した場合、NullClaw は `models.providers.<provider>` の通常の認証情報を使用します。
- `cost_class` はオプションのメタデータで、値は `free`、`cheap`、`standard`、`premium` のいずれかです。
- `quota_class` はオプションのメタデータで、値は `unlimited`、`normal`、`constrained` のいずれかです。

例:

```json
{
  "model_routes": [
    { "hint": "fast", "provider": "groq", "model": "llama-3.3-70b", "cost_class": "free", "quota_class": "unlimited" },
    { "hint": "balanced", "provider": "openrouter", "model": "anthropic/claude-sonnet-4", "cost_class": "standard", "quota_class": "normal" },
    { "hint": "deep", "provider": "openrouter", "model": "anthropic/claude-opus-4", "cost_class": "premium", "quota_class": "constrained" },
    { "hint": "vision", "provider": "openrouter", "model": "openai/gpt-4.1", "cost_class": "standard", "quota_class": "normal" }
  ]
}
```

注意事項:

- `model_routes` は、セッションが明示的なモデルに固定されていない場合にのみ使用されます。
- `deep` と `reasoning` の両方が設定されている場合、深い分析を要するプロンプトでは `deep` が優先されます。
- `/model` は直近の自動ルーティングの判定を表示するため、オペレーターはどのルートがなぜ選ばれたかを確認できます。
- 自動ルーティングされたセッションでは、クォータやレート制限によるエラーの後にそのルートを一時的に格下げし、クールダウンが終わるまでスキップします。
- ルートのメタデータはスコアリングを少し調整するだけです。曖昧なプロンプトは引き続き `balanced` に留まります。`fast` は確度の高い安価なタスク用に予約されており、深い分析を示す強いシグナルがあれば、より安価なルートよりも優先されます。

### `agents.list`

- `delegate` ツール、`/subagents spawn --agent`、`bindings` で使用される名前付きのエージェントプロファイルを定義します。
- 各エントリーでは `provider` + `model` を設定するか、`model.primary` に完全な `provider/model` 参照を設定できます。
- 例:

```json
{
  "agents": {
    "list": [
      {
        "id": "coder",
        "model": { "primary": "ollama/qwen3.5:cloud" },
        "system_prompt": "You're an experienced coder"
      }
    ]
  }
}
```

### サブエージェントプロファイル + ルーティング(実践的なパターン)

1 つの「オーケストレーター」エージェントに専門的なタスクを委任させたい場合は、このパターンを使用します:

1. 再利用可能なスペシャリストを `agents.list` の下に定義します。
2. 汎用のデフォルトは `agents.defaults` の下に置いておきます。
3. `bindings` を使って、特定のチャット/トピックをスペシャリストにルーティングします。
4. オペレーター側から明示的に単発の委任を行いたい場合は、`/subagents spawn --agent <agent-id> <task>` を使用します。

例:

```json
{
  "agents": {
    "defaults": {
      "model": { "primary": "openrouter/anthropic/claude-sonnet-4" }
    },
    "list": [
      {
        "id": "orchestrator",
        "model": { "primary": "openrouter/anthropic/claude-sonnet-4" },
        "system_prompt": "Coordinate tasks and delegate to specialists."
      },
      {
        "id": "coder",
        "model": { "primary": "openrouter/qwen/qwen3-coder" },
        "system_prompt": "You are focused on implementation and tests."
      },
      {
        "id": "researcher",
        "model": { "primary": "openrouter/openai/gpt-4.1" },
        "system_prompt": "You are focused on investigation and synthesis."
      }
    ]
  }
}
```

注意事項:

- `agents.list[].id` は、`/subagents spawn --agent <name>`、`delegate` ツールの `agent` 引数、`bindings[].agent_id` で使用される値です。
- チャットコマンドをシンプルに保つため、短く安定した ID(`coder`、`researcher`)を推奨します。
- スペシャリストのプロンプトは範囲を絞ってください。範囲の広いプロンプトは互いに重なり合い、ルーティングの明確さを損ないます。

#### `agents.list[].workspace_path`

名前付きエージェントをグローバルなワークスペースではなく専用のワークスペースから実行したい場合は、`workspace_path` を使用します。

例:

```json
{
  "agents": {
    "list": [
      {
        "id": "coder",
        "model": { "primary": "ollama/qwen2.5-coder:14b" },
        "system_prompt": "Focus on implementation and tests.",
        "workspace_path": "agents/coder"
      }
    ]
  }
}
```

動作:

- 相対パスは、`config.json` を含むディレクトリを基準に解決されます。
- 絶対パスはそのまま使用されます。
- 設定では `/` と `\` の両方を使用できます。ランタイムは現在の OS に合わせて区切り文字を正規化します。
- `workspace_path` は `system_prompt` を無効にしません。両方が設定されている場合、nullclaw は名前付きプロファイルのプロンプトを保持しつつ、その専用ワークスペースからブートストラップコンテキストも読み込みます。
- 初回使用時、ワークスペースが存在しなければ nullclaw がひな形を作成し、以下を作成します:
  - `AGENTS.md`
  - `SOUL.md`
  - `IDENTITY.md`
  - `MEMORY.md`

分離モデル:

- エージェントのファイル操作、Markdown のメモリファイル、ワークスペーススコープのコンテキストは、そのワークスペースを使用します。
- `workspace_path` が設定されている場合、エージェントには `agent:<agent-id>` という形式の永続的なメモリ名前空間も割り当てられます。
- この名前空間は以下で使用されます:
  - `nullclaw agent --agent <id>`
  - `/subagents spawn --agent <id> ...`
  - `bindings` を通じてその名前付きエージェントに解決される、ルーティングされたセッション

実際の効果:

- 2 つの名前付きエージェントが同じプロバイダー/モデルファミリーを共有しながら、それぞれ別の永続的なメモと別のワークスペースを保持できます。
- `workspace_path` だけではチャットはルーティングされません。ルーティングは引き続き `bindings`、`/bind`、または明示的な `--agent` / `/subagents spawn --agent` によって決まります。

### `messages.inbound`

- `debounce_ms` は、立て続けに届くプレーンテキストの受信メッセージの処理を遅らせ、複数の短い断片を 1 つのターンにまとめられるようにします。
- デフォルト: `3000`。
- デーモン経由でルーティングされる受信テキストと、Agent CLI の REPL に適用されます。
- `0` に設定すると無効になります。
- スラッシュコマンドとメディアを含む受信メッセージはデバウンスの対象外です。
- Telegram はチャンネル固有の分割メッセージ結合パスを維持しており、この設定はそのパスの基本デバウンス時間になります。

例:

```json
{
  "messages": {
    "inbound": {
      "debounce_ms": 1500
    }
  }
}
```

### `reliability`

- LLM プロバイダーに対するグローバルなリトライとフェイルオーバーの動作を設定します。
- `provider_retries`: 失敗した LLM リクエストをリトライする回数(デフォルト: 2)。
- `provider_backoff_ms`: リトライ間の指数バックオフの初期遅延(デフォルト: 500)。
- `fallback_providers`: プロバイダー指定のないモデルをプライマリープロバイダー以外にも展開する場合に試行する、プロバイダー名のリストです。
- `model_fallbacks`: モデルから、順序付きのフォールバックモデルのリストへのマッピングです。各フォールバックには、プレフィックスなしの別のモデル名、または明示的な `provider/model` 参照を指定できます。

例:

```json
{
  "reliability": {
    "provider_retries": 2,
    "provider_backoff_ms": 500,
    "fallback_providers": ["groq", "openai"],
    "model_fallbacks": [
      {
        "model": "anthropic/claude-sonnet-4",
        "fallbacks": ["openai/gpt-4o", "groq/llama-3.3-70b"]
      }
    ]
  }
}
```

注意事項:

- プレフィックスなしのモデル参照のフェイルオーバー順序: まずプライマリープロバイダー、次に列挙された各 `fallback_provider` の順です。
- `openai/gpt-4o` のようなプロバイダー指定付きのフォールバック参照は、そのプロバイダーに直接ルーティングされ、汎用的なプロバイダーの展開はスキップされます。
- `api_keys`: (オプション)レート制限(429)エラー時にローテーションするための追加の API キーのリストです。
### `identity` (AIEOS v1.1)

ランタイムのアイデンティティを AIEOS ドキュメントから取得したい場合は、このセクションを使用します。
設定すると、nullclaw は解析した AIEOS の内容を、`AGENTS.md` や `IDENTITY.md` などのワークスペースのアイデンティティファイルとあわせてシステムプロンプトに注入します:

```json
{
  "identity": {
    "format": "aieos",
    "aieos_path": "./identity/aieos.identity.json"
  }
}
```

同じドキュメントを設定内に直接インラインで記述することもできます:

```json
{
  "identity": {
    "format": "aieos",
    "aieos_inline": "{\"identity\":{\"names\":{\"first\":\"nullclaw-assistant\"},\"bio\":\"General-purpose autonomous assistant\"},\"linguistics\":{\"style\":\"concise\"},\"motivations\":{\"core_drive\":\"Help the operator finish tasks safely\"}}"
  }
}
```

最小限の AIEOS v1.1 サンプルファイル(`identity/aieos.identity.json`):

```json
{
  "identity": {
    "names": {
      "first": "nullclaw-assistant"
    },
    "bio": "General-purpose autonomous assistant"
  },
  "linguistics": {
    "style": "concise"
  },
  "motivations": {
    "core_drive": "Help the operator finish tasks safely"
  }
}
```

注意事項:

- AIEOS のペイロードは、`identity`、`psychology`、`linguistics`、`motivations`、`capabilities` などのトップレベルセクションを使用します。
- 保守性とバージョン管理での読みやすさのため、`aieos_path` を推奨します。
- `aieos_inline` は、完全に自己完結した単一の設定ファイルが必要な場合にのみ使用してください。
- `identity.format` はペイロードのソース(`aieos`)と一致させてください。
- 相対パスの `aieos_path` は、まずアクティブなワークスペースを基準に解決され、次に現在の作業ディレクトリを基準に解決されます。

### `channels`

- チャンネルの設定は `channels.<name>` の下に置きます。
- 複数アカウントに対応したチャンネルでは、通常 `accounts` ラッパーを使用します。

外部チャンネルプラグインの例:

```json
{
  "channels": {
    "external": {
      "accounts": {
        "wa-web": {
          "runtime_name": "whatsapp_web",
          "transport": {
            "command": "nullclaw-plugin-whatsapp-web",
            "args": ["--stdio"],
            "timeout_ms": 10000,
            "env": {
              "PLUGIN_TOKEN": "secret"
            }
          },
          "config": {
            "bridge_url": "http://127.0.0.1:3301",
            "allow_from": ["*"]
          }
        }
      }
    }
  }
}
```

外部チャンネルに関する注意事項:

完全なプロトコル、ライフサイクル、メタデータの規約、プラグイン作成者向けの
契約については、[外部チャンネルプラグイン](./external-channels.md) を参照してください。

- `runtime_name` は、ルーティング、バインディング、セッションキー、送信ディスパッチで使用される nullclaw のランタイムチャンネル ID です。組み込みチャンネルの名前や、他の設定済みチャンネルがすでに使用しているランタイム名を再利用してはいけません。
- `transport.command` と、オプションの `transport.args` によって、プラグインを子プロセスとして起動し、stdio 上の行区切り JSON-RPC で通信します。
- `transport.timeout_ms` はホストからプラグインへの RPC の待ち時間の上限です。1 つの壊れたプラグインが監視を何分も停滞させないよう、nullclaw は内部でコントロールプレーンの待ち時間も制限しています。
- `transport.env` はプラグインのプロセスにのみ渡されます。
- `config` は JSON オブジェクトである必要があります。これはプラグインの `start` リクエストに `params.config` として渡されます。
- プラグインは `get_manifest` に応答し、`start`/`send`/`stop` を処理する必要があります。プロセスが生きているかどうかだけでなく、切断されたサイドカーを監視側で検出できるよう、`health` の実装を推奨します。
- `get_manifest.result` には `protocol_version: 2` が含まれている必要があります。`capabilities.health`、`capabilities.streaming`、`capabilities.send_rich`、`capabilities.typing`、`capabilities.edit`、`capabilities.delete`、`capabilities.reactions`、`capabilities.read_receipts` はオプションの機能ビットです。
- `health.result` は明示的な真偽値(`healthy`)または明示的なヘルスシグナル(`ok`、`connected`、`logged_in`)を報告する必要があります。空のオブジェクトは無効として扱われます。QR/デバイスリンク方式のチャンネルでは、バックグラウンドの認証がまだ進行中の間、ここで `connected: false` や `logged_in: false` を報告します。
- `start.params` には、`name`、`account_id`、ホストが所有する `state_dir` を持つ、ネストされた `runtime` オブジェクトが含まれるようになりました。
- `start.result` には `started: true` が含まれている必要があります。`start` は QR スキャンや人間によるログインを待ってブロックするのではなく、ローカルの初期化が終わったら速やかに返すべきです。`send`、`send_rich`、`edit_message`、`delete_message`、およびタイピング/メッセージアクションの RPC は、プラグインが実際にそのアクションを受け付けた場合に `result.accepted: true` を返す必要があります。JSON-RPC の成功エンベロープだけでは不十分です。
- `send.params` には、ネストされた `runtime` と `message` オブジェクトが含まれるようになりました。テキストのペイロードは `message.text` を使用します。
- プラグインが `capabilities.edit=true` と `capabilities.delete=true` の両方を宣言している場合、`send.result` に `message_id` または `message { target?, message_id }` を含めることもできます。これにより、ネイティブの `.chunk` ストリーミングをサポートしないチャンネルでも、nullclaw は追跡中の下書きを更新し続けられます。
- `capabilities.streaming=true` の場合、nullclaw はモデルのストリーミング中に `.chunk` 段階の `send` イベントを送出することがあります。これが存在しないか `false` の場合、nullclaw は最終的なレスポンスのみを送出します。
- `capabilities.send_rich=true` の場合、ホストはネストされた `runtime` と `message { target, text, attachments, choices }` を指定して `send_rich` を呼び出すことがあります。
- `capabilities.typing=true` の場合、ホストはネストされた `runtime` と `recipient` を指定して `start_typing` / `stop_typing` を呼び出すことがあります。
- `capabilities.edit=true` / `capabilities.delete=true` の場合、ホストは `edit_message` / `delete_message` を呼び出すことがあります。
- `capabilities.reactions=true` または `capabilities.read_receipts=true` の場合、ホストは `set_reaction` と `mark_read` を呼び出すことがあります。
- `inbound_message.params.message` には `sender_id`、`chat_id`、`text` が含まれている必要があります。`metadata` がある場合は JSON オブジェクトでなければならず、`media` がある場合は空でない文字列の配列でなければなりません。
- 未知のチャンネルで、ルーティング/バインディングにダイレクトとグループのピアを区別させたい場合は、`metadata.peer_kind` と `metadata.peer_id` を含めてください。
- 未知/外部のチャンネルでは、`metadata.is_group`、`metadata.is_dm`、`metadata.typing_recipient` も設定できます。nullclaw はこのメタデータを、プロンプトの会話コンテキストと処理中インジケーターのルーティングに反映します。
- PR #265 の WhatsApp Web サイドカー用のリファレンスブリッジアダプターは `examples/whatsapp-web/nullclaw-plugin-whatsapp-web` にあります。
- 本番向けのコンパニオンリポジトリは、現在ツリー外で管理されています: [nullclaw/nullclaw-channel-baileys](https://github.com/nullclaw/nullclaw-channel-baileys) と [nullclaw/nullclaw-channel-whatsmeow-bridge](https://github.com/nullclaw/nullclaw-channel-whatsmeow-bridge)。
- `nullclaw channel start external` は最初に設定された外部アカウントを起動します。`nullclaw channel start <runtime_name>` は、`whatsapp_web` のような特定の設定済みランタイム名を対象にします。

Telegram の例:

```json
{
  "channels": {
    "telegram": {
      "accounts": {
        "main": {
          "bot_token": "123456:ABCDEF",
          "webhook_secret": "replace-with-random-telegram-webhook-secret",
          "allow_from": ["YOUR_TELEGRAM_USER_ID"]
        }
      }
    }
  }
}
```

WeChat の例:

```json
{
  "channels": {
    "wechat": {
      "accounts": {
        "main": {
          "callback_token": "wechat-callback-token",
          "encoding_aes_key": "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG",
          "app_id": "wx1234567890abcdef",
          "app_secret": "wechat-app-secret",
          "allow_from": ["openid_123"]
        }
      }
    }
  }
}
```

WeChat に関する注意事項:

- NullClaw は WeChat を組み込みの Webhook チャンネルとしてすでにサポートしています。公式アカウント(Official Account)のコールバックを受信するために外部プラグインは必要ありません。
- ゲートウェイの Webhook パスは `/wechat` です。複数の WeChat アカウントを設定している場合は `?account_id=<id>` を使用してください。
- 署名の検証には `callback_token` が必要です。
- `encoding_aes_key` はオプションですが、WeChat のコールバックが `encrypt_type=aes` に設定されている場合は必須です。
- `app_id` と `app_secret` は、WeChat のカスタムメッセージ API を通じて能動的なメッセージ送信を行いたい場合を除き、オプションです。
- `allow_from` が空の場合、受信メッセージは拒否されます。信頼できる OpenID を明示的に列挙するか、意図的に公開するアカウントの場合にのみ `"*"` を使用してください。
- バイナリが WeChat チャンネルなしでコンパイルされている場合は、`-Dchannels=wechat`(または `-Dchannels=all`)を指定してビルドしてください。

#### Weixin — WeChat iLink Bot(QR コードログイン)

`weixin` チャンネルは、QR コードによって WeChat iLink ボットを認可します。これは、署名付き Webhook を使用する
上記の `wechat` 公式アカウントチャンネルとは別のものです。

まず、ログインしてトークンを取得します:

```bash
nullclaw auth login weixin
```

これによりターミナルに QR コードが表示されます。WeChat でスキャンし、スマートフォン上で
認可を確定してください。コマンドは取得した `token` と、サービスがデフォルト以外のホストを返した場合は
その `base_url` を設定に保存します。

ログイン後、コマンドによって更新された Weixin のアカウントエントリーを編集し、
明示的な `allow_from` リストを設定してください。新しい設定では、下記のようなインラインのエントリーになります。
既存の `accounts` オブジェクトはそのレイアウトが維持されます。ログインコマンドに
`--proxy` の値を指定した場合は、同じアカウントに保存され、ランタイムの
API リクエストでも再利用されます。

```json
{
  "channels": {
    "weixin": {
      "account_id": "default",
      "token": "<bot-token-from-qr-login>",
      "base_url": "https://ilinkai.weixin.qq.com/",
      "proxy": null,
      "allow_from": ["<your-wechat-user-id>"]
    }
  }
}
```

Weixin チャンネルのフィールド:

| フィールド | デフォルト | 説明 |
|-------|---------|-------------|
| `account_id` | `"default"` | ルーティングとセッションキーで使用される内部のアカウント識別子 |
| `token` | `""` | `nullclaw auth login weixin` で取得したボットトークン(必須) |
| `base_url` | `https://ilinkai.weixin.qq.com/` | クエリ/フラグメントを含まない、絶対 HTTPS の iLink API URL(リージョンのリダイレクト後に変わる場合があります) |
| `proxy` | `null` | ランタイムの API リクエスト用の、オプションの `http://`、`https://`、または `socks5://` プロキシ URL |
| `allow_from` | `[]` | ボットへのメッセージ送信を許可する WeChat ユーザー ID(完全一致)。明示的に設定してください |

注意事項:

- `allow_from` に信頼できるユーザー ID(または意図的なワイルドカード `"*"`)が列挙されるまで、
  受信メッセージは一切受け付けられません。
- `nullclaw auth status weixin` は、空でないトークンが設定されているかどうかを報告します。
  リモートの iLink セッションを調べるものではありません。
- 設定済みのトークンを削除するには `nullclaw auth logout weixin` を使用します。
- プロキシが必要な場合は `nullclaw auth login weixin --proxy http://localhost:7890` を使用します。
  コマンドはこれを保存し、ログインとランタイムの API リクエストの両方で使用します。
- バイナリがこれなしでコンパイルされている場合は、`-Dchannels=weixin`(または `-Dchannels=all`)を指定してビルドしてください。
- `nullclaw gateway` は、設定された `weixin` のポーリングループを起動して監視します。
- 現在のアダプターは受信した会話をダイレクトメッセージとして扱い、テキストで返信します。
  グループのルーティングとメディア/ファイルの送信は実装されていません。

Telegram のフォーラムトピック:

- トピックごとのセッション分離は自動で行われます。`channels.telegram` の下に別途 `topic_id` フィールドはありません。
- オペレーターの実際の手順は次のとおりです:
  1. `agents.list` の下に名前付きエージェントプロファイルを設定する
  2. 対象の Telegram チャットまたはフォーラムトピックを開く
  3. `/bind <agent>` を実行する
- 特定のフォーラムトピックで特定のエージェントを使いたい場合は、`bindings` で `match.peer.id = "<chat_id>:thread:<topic_id>"` を指定して設定します。
- 同じ Telegram グループの残りの部分にフォールバック用のエージェントも設定したい場合は、プレーンなグループ ID `"<chat_id>"` に対する別のバインディングを追加します。
- `/bind status` は、現在有効なルートと利用可能なエージェント ID を表示します。
- `/bind clear` は、現在のアカウント/チャット/トピックに完全一致するバインディングのみを削除し、ルーティングをより広いマッチにフォールバックさせます。
- `/bind` は、現在の Telegram アカウントとピアに対する完全一致の `bindings[]` エントリーを書き込みます。
- `/bind status` は、完全一致のローカルな上書きと、継承されたより広いフォールバックを区別して表示します。
- トピック固有のバインディングは、ルートの優先度によりグループのフォールバックよりも優先されます。`bindings[]` 内の順序は関係ありません。
- `/bind` を Telegram のメニューに表示するかどうかは、`channels.telegram.accounts.<id>.binding_commands_enabled` で制御します。

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

この設定では、トピック `42` は `coder` にルーティングされ、フォーラムの残りの部分は `orchestrator` にフォールバックします。

> **ピア ID の形式に関する注意**: `bindings` 内のトピックのピア ID は、正規の `:thread:N` 形式(例: `"-1001234567890:thread:42"`)を使用する必要があります。従来の `#topic:N` 形式(例: `"-1001234567890#topic:42"`)は読み込み時に自動変換されますが、**非推奨** であり、ログに警告が表示されます。nullclaw のログ出力に `#topic:` が含まれている場合は、設定にコピーする際に `:thread:` に変換してください。`/bind` コマンドは常に正しい形式で自動的に保存します。

名前付きエージェントプロファイルとバインディングは別々の関心事です。`agents.list` は再利用可能なプロファイルを定義し、`bindings` は特定のチャット/トピックでどのプロファイルを使用するかを決定します。

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
          "webhook_secret": "replace-with-random-telegram-webhook-secret",
          "allow_from": ["YOUR_TELEGRAM_USER_ID"],
          "draft_previews": false,
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

オペレーターの手順:

- 対象のフォーラムトピック内で `/bind coder` を送信します。
- `nullclaw` が、そのトピックと Telegram アカウントに対する新しい完全一致の `bindings[]` エントリーを `~/.nullclaw/config.json` に書き込みます。
- そのトピックでの次のメッセージから、新しくルーティングされたエージェントプロファイルが使用されます。
- `/bind` で変更を永続化するには、`nullclaw` が `~/.nullclaw/config.json` への書き込み権限を持っている必要があります。

`draft_previews` について:

- `draft_previews=false` がデフォルトであり、推奨される設定です。
- 無効の場合でも、Telegram は返信の生成中にアクティビティ/入力中の表示を行いますが、一時的な `sendMessageDraft` のプレビューは使用しません。
- ライブの部分プレビューを明示的に使いたく、最終メッセージが届く前に Telegram がそれらの下書きを非表示にしたり置き換えたりする可能性を許容できる場合にのみ、`draft_previews=true` を設定してください。

`account_id` について:

- `account_id` は設定済みの Telegram アカウントエントリーを識別するもので、トピックやエージェントを識別するものではありません。
- 標準的な `channels.telegram.accounts` のレイアウトでは、オブジェクトのキーがアカウント ID になります。たとえば、`accounts.main` は `account_id = "main"` を意味します。
- `bindings` では、`match.account_id` によってバインディングを特定の 1 つの Telegram アカウントに限定します。
- `match.account_id` を省略した場合、そのバインディングはそのチャンネルの任意の Telegram アカウントにマッチします。
- 異なるアカウント ID が役立つのは、同じ nullclaw インスタンスで複数の Telegram ボットアカウント/トークンを実行する場合のみです。

### Web UI / ブラウザーリレー

ブラウザー UI / 拡張機能の WebSocket 経由のトラフィック(デフォルトでは `/ws`)には `channels.web` を使用します。

例:

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
          "allowed_origins": ["http://localhost:5173"]
        }
      }
    }
  }
}
```

実践的なルール:

- ペアリングを優先するローカルの UX のために、`listen = "127.0.0.1"` のままにしておいてください。
- ローカルトランスポートでは、認証なしの WebSocket アップグレードはループバックでのみ許可されます。これにより、UI がまず接続してから `pairing_request` を送信できます。
- ローカルのループバックペアリングは、固定の共有コードに依存しなくなりました。`pairing_request` では `payload.pairing_code` を省略でき、依然として `123456` を送信する従来のループバッククライアントとも互換性が保たれます。
- `listen` を `0.0.0.0` やその他のループバック以外のアドレスに変更した場合、WebSocket アップグレードの時点でチャンネルトークンが含まれている必要があります:
  - `ws://host:32123/ws?token=<auth_token>`
  - または `Authorization: Bearer <auth_token>`
- ループバック以外でバインドする場合、ソケットが認証される前にローカルの `pairing_request` が機能することは期待しないでください。ペアリング優先のフローは、設計上ループバック専用です。
- `message_auth_mode = "pairing"` は、各 `user_message` がペアリングフローで返された UI の `access_token` を持つ必要があることを意味します。
- `message_auth_mode = "token"` はローカルトランスポート専用で、設定または環境変数による固定のトークンが必要です。このモードでは、UI はペアリングの JWT の代わりに、各 `user_message` で `auth_token` を送信します。
- `auth_token` は WebSocket アップグレードを強化するもので、ループバック以外でバインドする場合は必須になります。
- WebSocket のエンドポイントには `/ws` を使用してください。`/pair` は HTTP ゲートウェイ API に属するもので、Web チャンネルの WebSocket フローのものではありません。
- ヘッドレス/LAN からのアクセスでは、ループバックにバインドした Web チャンネルの前段に SSH トンネルやリバースプロキシを置くのが、依然としてオペレーターにとって最も安全な方法です。

リモート/ヘッドレスの例:

```json
{
  "channels": {
    "web": {
      "accounts": {
        "default": {
          "transport": "local",
          "listen": "0.0.0.0",
          "port": 32123,
          "path": "/ws",
          "auth_token": "replace-with-long-random-token",
          "message_auth_mode": "token",
          "allowed_origins": ["https://chat-ui.example.com"]
        }
      }
    }
  }
}
```

配信への影響:

- 受信した Telegram のアップデートは、それを受信したアカウントによって処理されます。
- ルーティングにはその同じ `account_id` が使用されるため、`match.account_id = "main"` は `channels.telegram.accounts.main` を通じて受信したメッセージにのみマッチします。
- 返信は、そのメッセージを処理したのと同じ Telegram アカウント/ランタイムを通じて送り返されます。
- あるバインディングが `account_id = "main"` を使い、別のバインディングが `account_id = "sub"` を使う場合、それぞれ異なる設定済みの Telegram アカウントに適用されます。これだけで 1 つの Telegram アカウントのトラフィックが分割されるわけではありません。

ルール:

- 許可リストベースのチャンネルでは、`allow_from` が空の場合、受信メッセージは拒否されます。プライベートなボットでは明示的な ID/OpenID を設定してください。
- 許可リストベースのチャンネルでは、`allow_from: ["*"]` はすべての送信元を許可します。意図的に公開ボットにしたい場合にのみ使用してください。
- Telegram の Webhook では、`channels.telegram.accounts.<id>.webhook_secret` と Telegram の `X-Telegram-Bot-Api-Secret-Token` ヘッダーが一致する必要があります。
- Teams の受信 Webhook は、Microsoft の OpenID メタデータに対して Bot Framework の JWT ベアラートークンで認証されます。`channels.teams.accounts.<id>.webhook_secret` はオプションで、設定した場合は追加の `X-Webhook-Secret` チェックとして機能します。

Max の例:

```json
{
  "channels": {
    "max": {
      "accounts": {
        "main": {
          "bot_token": "MAX_BOT_TOKEN",
          "allow_from": ["YOUR_MAX_USER_ID"],
          "group_allow_from": ["YOUR_MAX_USER_ID"],
          "group_policy": "allowlist",
          "mode": "webhook",
          "webhook_url": "https://bot.example.com/max?account_id=main",
          "webhook_secret": "replace-with-random-secret",
          "require_mention": true,
          "streaming": true,
          "interactive": {
            "enabled": true,
            "ttl_secs": 900,
            "owner_only": true
          }
        }
      }
    }
  }
}
```

Max に関する注意事項:

- `channels.max.accounts` はアカウントエントリーのオブジェクトです。各オブジェクトのキーが、複数の Max ボットを区別する `account_id` になります。
- 本番環境では `mode = "webhook"` を推奨します。Max のドキュメントでは、ロングポーリングは開発/テスト向けとされており、本番環境では Webhook が推奨されています。
- `webhook_url` は HTTPS である必要があります。
- 複数アカウントの Webhook 構成では、各アカウントに一意の `webhook_secret` を設定するか、Webhook の URL に一意の `account_id` クエリを付けてください。例: `/max?account_id=main`。
- `allow_from` と `group_allow_from` には、Max の `user_id` の値またはユーザー名のどちらも指定できます。バインディングとルーティングには、安定している `user_id` を選ぶのが適切です。
- `require_mention = true` はグループチャットにのみ影響します。ダイレクトメッセージと `bot_started` のディープリンクは通常どおり機能します。
- nullclaw における Max のインラインボタンは 1 回限りです。有効なクリックの後、古いボタンが残らないように元のキーボードはクリアされます。

### Discord

Discord の例:

```json
{
  "channels": {
    "discord": {
      "accounts": {
        "default": {
          "token": "YOUR_DISCORD_BOT_TOKEN",
          "intents": 37377,
          "allow_from": ["YOUR_DISCORD_USER_ID"]
        }
      }
    }
  }
}
```

`allow_from` は明示的に設定してください。`allow_from` リストを省略するか空にすると、受信メッセージは拒否されます。意図的に公開ボットにしたい場合にのみ `["*"]` を使用してください。

ボットに通常のギルドメッセージを処理させたい場合は、Discord Developer Portal で MESSAGE CONTENT INTENT を有効にしてください。これがないと、Discord はほとんどのギルドのトラフィックでメッセージ内容を省略します。ダイレクトメッセージと、ボットをメンションしたメッセージには引き続き内容が含まれます。

ゲートウェイインテント(`intents`)はビットマスクです。デフォルトの 37377 = GUILDS (1) + GUILD_MESSAGES (512) + MESSAGE_CONTENT (32768) + DIRECT_MESSAGES (4096) です。カスタムのインテントは https://discord.com/developers/docs/topics/gateway#gateway-intents を参考に計算してください。

Discord のセットアップ手順:
1. https://discord.com/developers/applications でアプリケーションを作成します
2. Bot セクション → Add Bot → Reset Token(すぐにコピーしてください)
3. Privileged Gateway Intents → MESSAGE CONTENT INTENT を有効化 → Save
4. OAuth2 → URL Generator → Scopes: `bot`
5. Bot Permissions: Send Messages、Read Message History、Read Messages/View Channels
6. URL をコピーしてブラウザーで開き、サーバーを選択して認可します

現在の Discord 連携では、追加の OAuth スコープや `Administrator` のような昇格した権限は必要ありません。

複数ボットの構成では `accounts` ラッパーを使用します。各 `account_id` は、独立したセッション状態とルーティングを持つ、個別の Discord ボット接続を作成します:

```json
{
  "channels": {
    "discord": {
      "accounts": {
        "production": {
          "token": "PRODUCTION_BOT_TOKEN",
          "intents": 37377,
          "allow_from": ["ADMIN_USER_ID"]
        },
        "testing": {
          "token": "TESTING_BOT_TOKEN",
          "intents": 37377,
          "allow_from": ["DEV_USER_ID"]
        }
      }
    }
  }
}
```

チャンネル固有のバインディングでは、Discord のチャンネル ID とともに `peer.kind = "channel"` を使用します(開発者モードを有効化 → チャンネルを右クリック → ID をコピー):

```json
{
  "bindings": [
    {
      "agent_id": "coder",
      "match": {
        "channel": "discord",
        "account_id": "default",
        "peer": {"kind": "channel", "id": "CHANNEL_ID_HERE"}
      }
    }
  ]
}
```

ダイレクトメッセージのバインディングでは、ユーザー ID とともに `peer.kind = "direct"` を使用します:

```json
{
  "bindings": [
    {
      "agent_id": "personal",
      "match": {
        "channel": "discord",
        "account_id": "default",
        "peer": {"kind": "direct", "id": "USER_ID_HERE"}
      }
    }
  ]
}
```

パラメーター:
- `token`(必須)- Discord Developer Portal で取得したボットトークン
- `intents`(デフォルト: 37377)- ゲートウェイインテントのビットマスク
- `allow_bots`(デフォルト: false)- 他のボットからのメッセージを許可します。これを有効にしても、ボット自身が投稿したメッセージは常に無視されます
- `allow_from`(デフォルト: [])- ユーザー ID の許可リスト。省略または空のリストでは受信メッセージは拒否されます。`["*"]` はすべてのユーザーを明示的に許可します
- `require_mention`(デフォルト: false)- ギルドで応答するためにボットへのメンションを必須にします
- `guild_id`(オプション)- Discord サーバーのスコープ指定用に予約されています。現在のランタイムでは強制されません

NullClaw は 2000 文字を超えるメッセージを分割します(Discord API の制限)。

検証:
```bash
nullclaw channel start discord
nullclaw channel status
```

`nullclaw channel start discord` は、最初に設定された Discord アカウントのみを起動します。複数アカウントの検証には、`nullclaw gateway` を実行し、設定済みの各ボットにテストメッセージを送信してください。

よくある問題:
- ボットが DM または明示的なメンションにしか応答しない: MESSAGE CONTENT INTENT を有効にし、必要に応じてボットを再招待してください
- 「Privileged Intents」エラー: Discord Developer Portal で MESSAGE CONTENT INTENT を有効にしてください。認証済み(verified)のアプリでは Discord の承認が必要な場合もあります
- ボットがオフライン: `nullclaw service status` を確認し、トークンがリセットされていないか確認してください
- ギルドで応答がない: `require_mention` の設定を確認し、Read Messages 権限を確認してください

### `memory`

- `backend`: まずは `sqlite` から始めてください。利用可能なエンジン: `sqlite`、`markdown`、`clickhouse`、`postgres`、`redis`、`lancedb`、`lucid`、`memory`(LRU)、`api`、`none`。
- `auto_save`: 会話のメモリを自動的に永続化します。
- ハイブリッド検索と埋め込みの設定については、ルートの `config.example.json` を参照してください。

**注意**: `markdown_only` メモリプロファイルでは、最適な関連性スコアリングのために、時間減衰(半減期 30 日)付きのハイブリッド検索が自動的に有効になります。これにより、プレーンな Markdown ファイルでも時間を考慮した検索が行われます。

### `gateway`

推奨されるデフォルト:

- `host = "127.0.0.1"`
- `require_pairing = true`

直接パブリックに公開することは避けてください。外部からのアクセスが必要な場合はトンネルを使用してください。
ループバック以外でバインドしている場合、`/webhook`、`/a2a`、`/media/transcribe` などの汎用的なゲートウェイエンドポイントは、対話的なペアリングが無効であっても完全なゲートウェイのベアラートークンを必要とします。そのため、`require_pairing = true` のままにするか、`paired_tokens` を事前に設定してください。`/cron/*` は、後述する cron スコープの別の認証情報も受け付けます。
ループバック以外でバインドしている場合、`/pair` はループバックのクライアントからのみ受け付けます。ゲートウェイを公開する前に、最初のペアリングをローカルで行うか、`paired_tokens` を事前に設定してください。

cron の認証が必要な場合、ゲートウェイは起動時に `/cron/*` のみにスコープされたベアラートークンを作成します。ゲートウェイはトークンのハッシュのみを保持し、暗号化された認証情報を設定ディレクトリ内の `paired_token` にモード `0600` で書き込みます。これにより、`require_pairing = true` の場合やゲートウェイがパブリックにバインドされている場合(事前設定されたペアリングトークンがある構成を含む)でも、schedule/cron ツールが認証できます。この認証情報はゲートウェイを再起動するたびにローテーションされ、対話的な `/pair` のトークンではありません。他のベアラー認証情報と同様に、クライアントの IP には紐付けられていないため、設定ディレクトリが漏洩しないよう保護してください。`require_pairing = false` の匿名のループバックゲートウェイでは、この認証情報は作成されません。

| フィールド | デフォルト | 説明 |
|-------|---------|-------------|
| `host` | `"127.0.0.1"` | リッスンするアドレス |
| `port` | `3000` | リッスンするポート |
| `require_pairing` | `true` | すべての API リクエストでベアラートークンを必須にします |
| `allow_public_bind` | `false` | ループバック以外のアドレスへのバインドを許可します |
| `pair_rate_limit_per_minute` | `10` | IP ごとの 1 分あたりの `/pair` リクエストの最大数 |
| `webhook_rate_limit_per_minute` | `60` | 1 分あたりの、Webhook に類する認証済みリクエストの最大数。`/media/transcribe` でライブの音声チャンクを扱う場合は引き上げてください。 |
| `idempotency_ttl_secs` | `300` | 冪等なリクエストの結果をキャッシュする期間 |
| `max_body_size_bytes` | `65536` | HTTP リクエストボディの最大サイズ(バイト単位、64 KB)。画像、音声、ファイルのペイロードを受け付ける場合は引き上げてください(例: 64 MiB なら `67108864`)。 |
| `request_timeout_secs` | `30` | 受信 HTTP リクエストのソケット読み取りタイムアウト(秒)。低速な接続で大きなペイロードを受け付ける場合は引き上げてください。 |

### `tunnel`

ゲートウェイをパブリックなインターネットに公開するためのトンネルプロバイダーです。パブリック IP なしで実行する場合、Webhook ベースのチャンネルには必須です。

**プロバイダー:**

| プロバイダー | 説明 |
|----------|-------------|
| `none` | トンネルなし(デフォルト) |
| `cloudflare` | Cloudflare Tunnel |
| `ngrok` | ngrok トンネル |
| `tailscale` | Tailscale Funnel |
| `custom` | カスタムのトンネルコマンド |

**例: ngrok**

```json
{
  "tunnel": {
    "provider": "ngrok",
    "ngrok": {
      "auth_token": "YOUR_NGROK_AUTH_TOKEN",
      "domain": "your-domain.ngrok-free.app"
    }
  }
}
```

**例: Cloudflare**

```json
{
  "tunnel": {
    "provider": "cloudflare",
    "cloudflare": {
      "token": "YOUR_CLOUDFLARE_TUNNEL_TOKEN"
    }
  }
}
```

**例: Tailscale**

```json
{
  "tunnel": {
    "provider": "tailscale",
    "tailscale": {
      "funnel": true,
      "hostname": "nullclaw.ts.net",
      "auth_key": "tskey-auth-..."
    }
  }
}
```

**注意事項:**

- トンネルはゲートウェイより先に起動します。
- パブリック URL は起動時に表示され、`daemon_state.json` に書き込まれます。
- `tailscale.auth_key` はオプションです。`serve`/`funnel` を開始する前にマシンで `tailscale up` を自動実行させたい場合に使用します。
- `cloudflare.token`、`ngrok.auth_token`、`tailscale.auth_key` などのトンネルのシークレットは、`secrets.encrypt = true` の場合、保存時に暗号化されます。

### `autonomy`

- `level`: まずは `supervised` から始めてください。
- `level = "yolo"`: コマンドポリシーのチェックをバイパスします。信頼できるローカル環境でのデバッグにのみ使用してください。
- `workspace_only`: ファイルアクセスの範囲を制限するため、`true` のままにしておいてください。
- `max_actions_per_hour`: 最初は控えめな制限にしておいてください。
- `block_high_risk_commands`(デフォルト: `true`): `rm`、`sudo`、`mkfs`、`dd`、`shutdown`、`ssh` などの破壊的なコマンドをブロックします。
- `block_medium_risk_commands`(デフォルト: `true`): 中リスクのコマンドをブロックします。これには `curl`、`wget`、`nc`、`scp`、`ftp`、`telnet` などのネットワーク/転送コマンドや、`git commit`、`npm install`、`touch`、`mkdir` などの状態を変更するコマンドが含まれます。高リスクのコマンドは引き続きブロックしつつ、これらを許可したい場合は `false` に設定してください。
- `require_approval_for_medium_risk`(デフォルト: `true`): `block_medium_risk_commands` が `false` の場合、`supervised` モードで中リスクのコマンドを実行する前に明示的な承認を必須にします。
- `allowed_commands`: 許可するコマンドのベース名の明示的なリストです。ワイルドカードには `["*"]` を使用します(完全な自律モード専用)。このリストに関係なく、高リスクおよび中リスクのランタイムゲートは引き続き適用されます。

### `security`

- `sandbox.backend = "auto"`: 利用可能なサンドボックスのバックエンドを自動的に選択します。
- `audit.enabled = true`: 追跡可能性のために推奨されます。

### 応用: Web 検索 + フルシェル(高リスク)

管理された環境でのみ使用してください:

```json
{
  "http_request": {
    "enabled": true,
    "allowed_domains": ["192.168.1.10", "*.internal.example.com"],
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

注意事項:

- `search_base_url`(web_search ツール用): `https://host[/search]`、またはローカル/プライベートの `http://host[:port][/search]` URL である必要があります。HTTP は localhost/プライベートホストに対してのみ許可されます(例: `http://localhost:8888`、`http://192.168.1.10:8888`)。この URL は、`web_search` ツールが SearXNG インスタンスに問い合わせる際に使用されます。
- `allowed_commands: ["*"]` と `allowed_paths: ["*"]` は、実行範囲を大幅に広げます。
- `http_request.allowed_domains`: `http_request` ツールと `web_fetch` ツールで SSRF 保護をバイパスするドメインです。
  - `[]`(空): すべてのドメインが SSRF チェックを通過します(デフォルト、最も安全)。
  - `["example.com"]`: 指定したドメインのみ SSRF 保護をスキップします。
  - `["*.example.com"]`: すべてのサブドメインにマッチします(例: `api.example.com`、`www.example.com`)。
  - `["192.168.1.10"]`: IP アドレスも許可リストに追加できます(完全一致のみ、CIDR 範囲はサポートされていません)。
  - `["*"]`: **危険** - すべてのドメインが SSRF 保護と DNS ピン留めをスキップします。DNS を自分で管理しており、任意の IP アドレスへのアクセスを許可する必要がある、信頼できるネットワーク環境でのみ使用してください。これは事実上 SSRF 保護を無効にします。
  - **例**: SearXNG が `192.168.1.10` で動作している場合、`http_request` ツールからアクセスするには `"192.168.1.10"` を追加します。
  - **セキュリティ上のトレードオフ**: 許可リストに含まれるドメインは DNS ピン留めをスキップするため、プライベート IP へのアクセスが可能になります。これは、DNS リバインディング保護と引き換えに運用上の柔軟性を得るものです。
  - **HTTPS 限定ポリシー**: `http_request` ツールと `web_fetch` ツールは `https://` の URL を必要とします。セキュリティのため、プレーンな HTTP は拒否されます。注: これは、ローカルホストに対して HTTP を許可している `web_search` ツールの `search_base_url` には影響しません。
  - **チェックの順序**: DNS を利用したデータ持ち出し攻撃を防ぐため、許可リストは DNS 解決の「前」にチェックされます。

## 設定変更後の検証

設定を変更するたびに:

```bash
nullclaw doctor
nullclaw status
nullclaw channel status
```

ゲートウェイ/チャンネルを変更した場合は、以下も実行してください:

```bash
nullclaw gateway
```

## 次のステップ

- 編集のたびに `nullclaw doctor` と `nullclaw status` を実行し、設定が引き続き問題なく読み込まれることを確認してください
- 運用上のチェック、サービスモード、トラブルシューティングの流れについては [使い方と運用](./usage.md) を参照してください
- より広い自律性、パブリックバインド、ワイルドカードの許可リストを有効にする前に、[セキュリティ](./security.md) を確認してください

## 関連ページ

- [インストール](./installation.md)
- [使い方と運用](./usage.md)
- [セキュリティ](./security.md)
- [Gateway API](./gateway-api.md)
