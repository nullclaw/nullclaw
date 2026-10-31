# Gateway API

デフォルトのゲートウェイエンドポイント: `http://127.0.0.1:3000`

## ページガイド

**このページの対象読者**

- 外部システムをローカルゲートウェイに接続するオペレーター
- ペアリング、Bearer トークン認証、webhook 配信をテストするインテグレーター
- HTTP インターフェースがデフォルトで何を公開しているかを確認するレビュアー

**次に読むもの**

- ループバックやトンネルのデフォルトを超えてゲートウェイのパスを公開する前に、[セキュリティ](./security.md) を開いてください
- これらの例の背後にある具体的な `gateway` キーやチャンネルキーが必要な場合は、[設定](./configuration.md) を開いてください
- ゲートウェイの動作に関するランタイムチェック、再起動、トラブルシューティングについては、[使い方と運用](./usage.md) を開いてください

**以下のページから来た場合**

- [使い方と運用](./usage.md): このページでは、ゲートウェイのヘルスチェックと webhook チェックの背後にあるエンドポイントレベルの詳細を説明します
- [セキュリティ](./security.md): セキュリティレビューで具体的な HTTP 認証とエンドポイントの範囲が必要になったときは、このページを参照してください
- [設定](./configuration.md): `gateway` 設定を編集した後、API に関わる動作を検証するためにこのページに戻ってください

## エンドポイント

| エンドポイント | メソッド | 認証 | 説明 |
|---|---|---|---|
| `/health` | GET | なし | ヘルスチェック |
| `/pair` | POST | `X-Pairing-Code` | ワンタイムのペアリングコードを Bearer トークンと交換します（ゲートウェイがパブリックにバインドされている場合はループバックのみ） |
| `/webhook` | POST | `Authorization: Bearer <token>` | メッセージペイロードを送信します: `{"message":"..."}` |
| `/media/transcribe` | POST | `Authorization: Bearer <token>` | 設定された STT プロバイダーを通じて base64 音声ペイロードを文字起こしします |
| `/cron` | GET | 認証が必要な場合は cron スコープの Bearer またはゲートウェイのフル Bearer | 実行中のデーモンからライブのスケジューラージョブを一覧表示します |
| `/cron/add` | POST | 認証が必要な場合は cron スコープの Bearer またはゲートウェイのフル Bearer | ライブの cron ジョブを追加またはスケジュールします |
| `/cron/remove` | POST | 認証が必要な場合は cron スコープの Bearer またはゲートウェイのフル Bearer | `id` を指定してライブの cron ジョブを削除します |
| `/cron/pause` | POST | 認証が必要な場合は cron スコープの Bearer またはゲートウェイのフル Bearer | `id` を指定してライブの cron ジョブを一時停止します |
| `/cron/resume` | POST | 認証が必要な場合は cron スコープの Bearer またはゲートウェイのフル Bearer | `id` を指定してライブの cron ジョブを再開します |
| `/cron/update` | POST | 認証が必要な場合は cron スコープの Bearer またはゲートウェイのフル Bearer | ライブの cron ジョブを部分的に更新します |
| `/telegram` | POST | `channels.telegram.accounts.<id>.webhook_secret` に一致する `X-Telegram-Bot-Api-Secret-Token` | Telegram の受信 webhook |
| `/whatsapp` | GET | クエリパラメーター | Meta の webhook 検証 |
| `/whatsapp` | POST | Meta の署名 | WhatsApp の受信 webhook |
| `/max` | POST | 設定されている場合は `X-Max-Bot-Api-Secret` | Max の受信 webhook 配信 |
| `/api/messages` | POST | `Authorization: Bearer <Bot Framework JWT>` と任意の `X-Webhook-Secret` | Teams Bot Framework の受信 webhook |
| `/.well-known/agent-card.json` | GET | なし | A2A Agent Card の検出（公開） |
| `/a2a` | POST | `Authorization: Bearer <token>` | A2A JSON-RPC 2.0 エンドポイント |

## クイック例

### 1) ヘルスチェック

```bash
curl http://127.0.0.1:3000/health
```

### 2) ペアリングしてトークンを取得する

```bash
curl -X POST \
  -H "X-Pairing-Code: PAIRING_CODE" \
  http://127.0.0.1:3000/pair
```

期待される結果: Bearer トークンのレスポンス（正確な JSON の形はバージョンによって異なる場合があります）。

### 3) webhook メッセージを送信する

```bash
curl -X POST \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"message":"hello from webhook"}' \
  http://127.0.0.1:3000/webhook
```

### 4) ライブの cron ジョブを一覧表示する

```bash
curl -X GET \
  -H "Authorization: Bearer YOUR_TOKEN" \
  http://127.0.0.1:3000/cron
```

### 5) ライブの cron ジョブを追加する

```bash
curl -X POST \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"expression":"*/15 * * * *","command":"echo hello"}' \
  http://127.0.0.1:3000/cron/add
```

`/cron/add` は、`{"delay":"10m","command":"echo later"}` のようなワンショットのペイロードや、`{"expression":"0 * * * *","prompt":"Summarize alerts","model":"openrouter/anthropic/claude-sonnet-4"}` のようなエージェントペイロードも受け付けます。

### 6) Max の webhook 配信

単一アカウントの例:

```bash
curl -X POST \
  -H "Content-Type: application/json" \
  -H "X-Max-Bot-Api-Secret: YOUR_MAX_SECRET" \
  -d '{"update_type":"bot_started","chat_id":100,"timestamp":1710000000000,"user":{"user_id":42,"first_name":"Igor"}}' \
  http://127.0.0.1:3000/max
```

複数アカウントの例:

```bash
curl -X POST \
  -H "Content-Type: application/json" \
  -H "X-Max-Bot-Api-Secret: YOUR_MAX_SECRET" \
  -d '{"update_type":"message_created","timestamp":1710000000000,"message":{"sender":{"user_id":42,"first_name":"Igor"},"recipient":{"chat_id":100,"chat_type":"dialog"},"body":{"mid":"m1","text":"ping"}}}' \
  "http://127.0.0.1:3000/max?account_id=main"
```

Max webhook に関する注意:

- `nullclaw` は `/max` を、まず `account_id` クエリ、次に `X-Max-Bot-Api-Secret` によって、設定済みの Max アカウントにルーティングします。
- `channels.max.accounts.<id>.webhook_secret` が設定されている場合、このヘッダーは必須で、完全に一致する必要があります。
- Max 側で設定する webhook URL には HTTPS を使用してください。

Teams webhook に関する注意:

- `nullclaw` は、アクティビティを受け付ける前に、Bot Framework の Bearer トークンを Microsoft の OpenID メタデータと署名鍵に照らして検証します。
- トークンの発行者は `https://api.botframework.com` でなければならず、オーディエンスは設定された Teams の `client_id` と一致し、トークンの `serviceUrl` はアクティビティ本文と一致する必要があります。
- Teams の `channelId` の endorsement は、公開されている Bot Framework の鍵メタデータに基づいて強制されます。
- `channels.teams.accounts.<id>.webhook_secret` が設定されている場合、`X-Webhook-Secret` も完全に一致する必要があります。

## メディアの文字起こし

`POST /media/transcribe` はローカルのオーケストレーター向けです。`/webhook` や `/a2a` と同じ Bearer トークン認証が必要で、設定された `tools.media.audio` の STT モデルを使用します。

リクエスト:

```json
{
  "audio_base64": "BASE64_AUDIO_BYTES",
  "mime_type": "audio/webm;codecs=opus",
  "source": "mic",
  "language": "en"
}
```

レスポンス:

```json
{
  "text": "transcribed speech",
  "source": "mic",
  "language": "en",
  "mime_type": "audio/webm;codecs=opus"
}
```

注意:

- `audio_base64` は必須です。`mime_type` のデフォルトは `audio/ogg` です。
- `audio/*` の MIME タイプのみが受け付けられます。
- デスクトップ音声をライブでチャンク送信する場合は、`gateway.max_body_size_bytes`、`gateway.request_timeout_secs`、`gateway.webhook_rate_limit_per_minute` を引き上げてください。
- `tools.media.audio.models[0]` で STT のプロバイダー/モデル/エンドポイントを選択します。そのプロバイダーにキーがない場合、NullClaw は利用可能であればキーが設定された OpenAI/Groq/Telnyx プロバイダーにフォールバックします。
- カスタム STT エンドポイントは、リモートホストの場合 HTTPS でなければなりません。プレーンな HTTP はローカル/プライベートのエンドポイントでのみ受け付けられ、クエリやフラグメントを含む URL は拒否されます。

## A2A（Agent-to-Agent Protocol）

NullClaw は JSON-RPC 2.0 上で [Google の A2A プロトコル v0.3.0](https://github.com/google/A2A) を実装しており、A2A 互換のあらゆるエージェントやクライアントとの相互運用が可能です。

### 設定

`~/.nullclaw/config.json` に追加します:

```json
{
  "a2a": {
    "enabled": true,
    "name": "My Agent",
    "description": "General-purpose AI assistant",
    "url": "https://your-public-url.example.com",
    "version": "0.3.0"
  }
}
```

| フィールド | デフォルト | 説明 |
|-------|---------|-------------|
| `enabled` | `false` | A2A エンドポイントを有効にします |
| `name` | `"NullClaw"` | Agent Card に表示されるエージェント名 |
| `description` | `"AI assistant"` | エージェントの説明 |
| `url` | `""` | 公開 URL（Agent Card と `supportedInterfaces` で使用） |
| `version` | `"1.0.0"` | エージェントのバージョン文字列 |
| `multi_modal` | `false` | Agent Card でマルチモーダル対応を通知します。設定されたモデルが画像入力をサポートしている場合は `true` に設定してください。ゲートウェイは起動時にモデルを検査してこれを自動的に設定します。必要に応じて手動で上書きしてください。 |

**マルチモーダル対応**

`multi_modal` が `true` の場合、Agent Card の capabilities オブジェクトに `"multi_modal": true` が含まれ、エージェントが画像添付を受け付けることを A2A クライアントに伝えます。受信する A2A メッセージには、`text` パートと並んで `inlineData` パート（base64 エンコードされた画像）が含まれる場合があります。ゲートウェイはそれらを `[IMAGE: <mime_type>]` マーカーとしてモデルに転送します。

大きな画像ペイロードを受け付けるには、`gateway` 設定ブロックでゲートウェイの HTTP ボディ上限とソケット読み取りタイムアウトを引き上げてください（[configuration.md](./configuration.md) の `gateway` セクションを参照）:

```json
{
  "gateway": {
    "max_body_size_bytes": 67108864,
    "request_timeout_secs": 120
  }
}
```

### Agent Card の検出

```bash
curl http://127.0.0.1:3000/.well-known/agent-card.json
```

capabilities、skills、セキュリティスキーム、サポートされるインターフェースを含む Agent Card を返します。認証は不要です。

### JSON-RPC メソッド

すべてのメソッドは、`/pair` で取得した Bearer トークンを使って `POST /a2a` 経由で呼び出します。

| メソッド | 説明 |
|--------|-------------|
| `message/send` | メッセージを送信し、完了したタスクを受け取ります |
| `message/stream` | メッセージを送信し、イベントの SSE ストリームを受け取ります |
| `tasks/get` | ID でタスクを取得します（`historyLength` をサポート） |
| `tasks/cancel` | アクティブなタスクをキャンセルします |
| `tasks/list` | 任意の `state`/`contextId` フィルターでタスクを一覧表示します |
| `tasks/resubscribe` | 既存のタスクの SSE ストリームを再開します |

### タスクのライフサイクル

```
submitted → working → completed
                    → failed
                    → canceled
                    → input-required
                    → auth-required
                    → rejected
```

終了状態: `completed`、`failed`、`canceled`、`rejected`。

### 例

**メッセージを送信する:**

```bash
curl -X POST \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "message/send",
    "params": {
      "message": {
        "messageId": "msg-1",
        "role": "user",
        "parts": [{"kind": "text", "text": "What is nullclaw?"}]
      }
    }
  }' \
  http://127.0.0.1:3000/a2a
```

**レスポンスをストリーミングする（SSE）:**

```bash
curl -N -X POST \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "message/stream",
    "params": {
      "message": {
        "messageId": "msg-2",
        "role": "user",
        "parts": [{"kind": "text", "text": "Explain A2A protocol"}]
      }
    }
  }' \
  http://127.0.0.1:3000/a2a
```

**タスクを取得する:**

```bash
curl -X POST \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tasks/get","params":{"id":"task-1"}}' \
  http://127.0.0.1:3000/a2a
```

**タスクをキャンセルする:**

```bash
curl -X POST \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":3,"method":"tasks/cancel","params":{"id":"task-1"}}' \
  http://127.0.0.1:3000/a2a
```

### マルチターンの会話

メッセージに `contextId` を含めると、タスクを1つの会話にまとめられます。同じ `contextId` を持つすべてのメッセージは、セッション状態と会話履歴を共有します:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "message/send",
  "params": {
    "message": {
      "messageId": "msg-3",
      "contextId": "my-conversation",
      "role": "user",
      "parts": [{"kind": "text", "text": "Follow-up question"}]
    }
  }
}
```

### エラーコード

| コード | 名前 | 説明 |
|------|------|-------------|
| -32700 | JSONParseError | 無効な JSON ペイロード |
| -32600 | InvalidRequestError | リクエストの検証エラー |
| -32601 | MethodNotFoundError | 不明なメソッド |
| -32602 | InvalidParamsError | パラメーターが欠落しているか無効 |
| -32603 | InternalError | サーバー側のエラー |
| -32001 | TaskNotFoundError | タスク ID が見つからない |
| -32002 | TaskNotCancelableError | タスクがすでに終了状態にある |
| -32003 | PushNotificationNotSupportedError | プッシュ通知はサポートされていない |
| -32005 | ContentTypeNotSupportedError | 互換性のないコンテンツタイプ |
| -32007 | AuthenticatedExtendedCardNotConfiguredError | 拡張カードが利用できない |

## セキュリティガイダンス

1. `gateway.require_pairing = true` を維持してください。
2. ゲートウェイはループバック（`127.0.0.1`）に置いたままにし、外部にはトンネル/プロキシ経由で公開してください。
3. 意図的にループバック以外へのバインドを使用する場合でも、汎用エンドポイント（`/webhook`、`/a2a`、`/media/transcribe`）は、対話的なペアリングが無効になっていてもゲートウェイのフル Bearer トークンを必要とします。`/pair` を使用しない場合は、`gateway.paired_tokens` を事前に設定してください。`/cron/*` は専用の cron スコープの Bearer も受け付けます。
4. ループバック以外へのバインドでは、`/pair` はループバックのクライアントのみを受け付けます。最初のペアリングはローカルで行うか、ポートを公開する前に `gateway.paired_tokens` を事前に設定してください。
5. Bearer トークンはシークレットとして扱い、コミットしたりログに出力したりしないでください。
6. Max の webhook シークレットも同様に扱ってください。アカウントごとにランダムに生成し、1つのシークレットを複数のボットで使い回さないでください。
7. cron 認証が必要な場合、ゲートウェイは起動時に `/cron/*` のみにスコープされた Bearer を作成し、そのハッシュを保持して、暗号化された認証情報を設定ディレクトリ内の `paired_token` にモード `0600` で書き込みます。schedule/cron ツールは、コントロールプレーンのリクエストのためにこのファイルを読み取ります。このトークンはゲートウェイの再起動のたびにローテーションされ、webhook、A2A、メディア、その他の管理ルートを認可することはできません。それでも IP に紐づいたローカル起点の証明ではなく Bearer 認証情報であることに変わりはないため、設定ディレクトリが漏えいしないよう保護してください。`require_pairing = false` の匿名ループバックゲートウェイでは作成されません。

## 次のステップ

- 公開範囲、ペアリング、トークンの取り扱いに関する前提を変更する前に、[セキュリティ](./security.md) を確認してください
- このページの例の背後にある設定については、[設定](./configuration.md) を確認してください
- ゲートウェイの起動、ヘルスチェック、変更後の検証フローについては、[使い方と運用](./usage.md) を使用してください

## 関連ページ

- [設定](./configuration.md)
- [使い方と運用](./usage.md)
- [セキュリティ](./security.md)
- [README](./README.md)
