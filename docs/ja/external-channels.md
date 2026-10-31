# 外部チャンネルプラグイン

このページでは、`channels.external` ランタイムと、チャンネル固有のコードをコアにマージせずに
新しいメッセージングチャンネルを追加するためのプラグインプロトコルについて説明します。

## ページガイド

**このページの対象読者**

- 外部チャンネルを `config.json` に組み込むオペレーター
- 新しいチャンネルブリッジを実装するプラグイン作成者
- 新しい統合をコアに含めるべきか、プラグインにすべきかをレビューするメンテナー

**次に読むページ**

- 設定ファイル全体のコンテキストについては [設定](./configuration.md) を開いてください
- より広いランタイムモデルを知りたい場合は [アーキテクチャ](./architecture.md) を開いてください
- 本番デプロイを検証する際は [使い方と運用](./usage.md) を開いてください

## 外部チャンネルが存在する理由

`channels.external` は、コミュニティ製やサイト固有のチャンネルのためのクリーンな拡張経路です。
設計上の目標は次のとおりです。

- チャンネル固有の SDK、サイドカー、ブリッジロジックを nullclaw コアの外に置く
- プロセス内での ABI/プラグインロードの複雑さを避ける
- チャンネルごとのコードを別のリポジトリや別の言語で管理できるようにする
- ホスト側の契約を狭く、明示的で、監視しやすいものに保つ

ホストとプラグインの境界は次のとおりです。

- トランスポート: `stdin`/`stdout` 上の行区切り JSON-RPC
- プロセスモデル: nullclaw が起動する子プロセス
- ルーティング面: 汎用的な `Channel` 操作のみ
- チャンネル固有の動作: すべてプラグイン内で実装

## 使用すべき場面

次のような場合は外部チャンネルプラグインを使用してください。

- チャンネルが大きな SDK や Zig 以外の依存関係を必要とする
- 統合がニッチ、実験的、またはオペレーター固有のものである
- チャンネルをローカルのサイドカーやブリッジとして表現するのが最適である
- nullclaw のリリースサイクルとは独立して開発を進めたい

次のような場合は使用しないでください。

- その機能が実際にはチャンネルではなく、プロダクト/アプリ層である
- コアのルーティング、メモリ、セキュリティ、エージェントのセマンティクスを変更する必要がある
- その統合はメッセージトランスポートとしてよりも、ツール/MCP として表現するほうが適している

## 設定モデル

外部チャンネルは `channels.external.accounts.<id>` の下に置かれます。

例:

```json
{
  "channels": {
    "external": {
      "accounts": {
        "wa-web": {
          "runtime_name": "whatsapp_web",
          "transport": {
            "command": "/opt/nullclaw/plugins/nullclaw-plugin-whatsapp-web",
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

フィールド:

- `runtime_name`
  ルーティング、バインディング、セッションキー、デーモンのディスパッチ、および
  `nullclaw channel start <runtime_name>` で使用されるランタイムチャンネル名です。
- `transport.command`
  プラグインプロセスの実行ファイルのパスまたはコマンド名です。
- `transport.args`
  任意の引数ベクターです。
- `transport.env`
  プラグインプロセスにのみ渡される任意の環境変数です。
- `transport.timeout_ms`
  ホストの RPC 待機時間に対するアカウントごとの上限です。監視上重要なリクエストについては、
  ホストは内部でさらに短い上限を適用します。
- `config`
  プラグインの `start` RPC に `params.config` として転送される不透明な JSON オブジェクトです。

検証ルール:

- `runtime_name` は空であってはならず、英字、数字、`_`、`-`、`.` のみを含む必要があります
- `runtime_name` は、組み込みのランタイムチャンネルと設定済みのランタイムチャンネル全体でグローバルに一意である必要があります
- `transport.command` は必須です
- `transport.timeout_ms` は `[1, 600000]` の範囲内である必要があります
- `config` は JSON オブジェクトである必要があります

## ランタイムアーキテクチャ

ランタイムでは、ホストが汎用的な `ExternalChannel` を作成し、次の処理を行います。

1. プラグインの子プロセスを起動する
2. プラグインのマニフェストを取得して検証する
3. `start` を送信する
4. 汎用的な `Channel` 操作を JSON-RPC リクエストにマッピングする
5. `inbound_message` 通知を受け取り、バスに発行する
6. 上限付きのプローブでプラグインのヘルスを監視する

重要な特性:

- 設定された 1 つのアカウントが 1 つのプラグイン子プロセスに対応します
- プラグインは他のチャンネルランタイムと同様に監視されます
- プラグインの stdout は JSON-RPC の行専用に予約されています
- プラグインの stderr は診断用に使用できます

## トランスポート契約

トランスポートは、stdio 上の行区切り JSON-RPC 2.0 です。

ルール:

- 各リクエスト、レスポンス、通知は 1 行に収まる必要があります
- stdout には JSON-RPC のみを含める必要があります
- stderr は自由形式で、プロトコルには関与しません
- リクエストとレスポンスの対応付けには JSON-RPC の `id` を使用します
- 以下で必須とされている箇所では、`params` と `result` のペイロードは JSON オブジェクトである必要があります

## マニフェスト

ホストは次のように呼び出します。

```json
{"jsonrpc":"2.0","id":1,"method":"get_manifest","params":{}}
```

プラグインは次のように応答する必要があります。

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "protocol_version": 2,
    "capabilities": {
      "health": true,
      "streaming": false,
      "send_rich": false,
      "typing": false,
      "edit": false,
      "delete": false,
      "reactions": false,
      "read_receipts": false
    }
  }
}
```

ルール:

- `protocol_version` は `2` と等しい必要があります
- `capabilities` は任意です
- 存在しないケイパビリティビットは未サポートとして扱われます

ケイパビリティの意味:

- `health`
  プラグインは `health` RPC を実装しており、チャンネルレベルのヘルスを報告できます。
- `streaming`
  プラグインはモデルのストリーミングによる段階的な `.chunk` 送信イベントを受け付けます。
- `send_rich`
  プラグインは `send_rich` を実装しています。
- `typing`
  プラグインは `start_typing` と `stop_typing` を実装しています。
- `edit`
  プラグインは、ホスト管理のフォローアップ更新のために `edit_message` を実装しています。
- `delete`
  プラグインは、ホスト管理のクリーンアップのために `delete_message` を実装しています。
- `reactions`
  プラグインは `set_reaction` を実装しています。
- `read_receipts`
  プラグインは `mark_read` を実装しています。

## ライフサイクル RPC

### `start`

ホストのリクエスト:

```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "start",
  "params": {
    "runtime": {
      "name": "whatsapp_web",
      "account_id": "wa-web",
      "state_dir": "/home/user/.nullclaw/workspace/state/channels/external/whatsapp_web/wa-web"
    },
    "config": {
      "bridge_url": "http://127.0.0.1:3301",
      "allow_from": ["*"]
    }
  }
}
```

必須の成功レスポンス:

```json
{"jsonrpc":"2.0","id":2,"result":{"started":true}}
```

注意:

- `runtime.state_dir` は、プラグインアカウント用のホスト所有の永続ストレージです
- プラグインは `config` を不透明なプラグインローカル設定として扱うべきです
- `result.started: true` を含まない JSON-RPC の成功エンベロープは拒否されます
- `start` は、プラグインプロセスが自身のランタイム状態を初期化したら速やかに返すべきです。
  QR スキャン、デバイスのペアリング、人手によるログイン手順のために `start` を
  保留したままにしないでください
- 初回実行時の認証がまだ保留中の場合は、`started: true` を返し、その準備未完了の状態を
  `health` を通じて公開してください

### `stop`

ホストのリクエスト:

```json
{"jsonrpc":"2.0","id":3,"method":"stop","params":{}}
```

ホストは有効な JSON-RPC の成功レスポンス以外に特別なペイロードを要求しませんが、
それでも result オブジェクトを返すことを推奨します。

## Health RPC

`capabilities.health=true` の場合、ホストは次のように呼び出すことがあります。

```json
{"jsonrpc":"2.0","id":4,"method":"health","params":{}}
```

受け付けられるレスポンスの形式:

```json
{"jsonrpc":"2.0","id":4,"result":{"healthy":true}}
```

または

```json
{"jsonrpc":"2.0","id":4,"result":{"ok":true,"connected":true,"logged_in":true}}
```

ルール:

- `healthy` が存在する場合はブール値である必要があります
- それ以外の場合は、`ok`、`connected`、`logged_in` のうち少なくとも 1 つが存在する必要があります
- 空の `{}` の result は無効です
- プラグインが `health` をサポートしていない場合は、スタブの成功を返すのではなく、
  ケイパビリティビットを省略してください

推奨される非同期認証の動作:

- 起動は成功したが認証がまだ保留中の場合は、`start` に即座に応答し、
  `health` から `connected: false` および/または `logged_in: false` を報告してください
- `healthy: false` は、単に QR スキャンを待っている場合ではなく、
  プラグインランタイム自体が正しく動作していない場合のために取っておいてください
- ログインが完了したら、ホストがプラグインを再起動しなくても、`health` は
  `connected: true` と `logged_in: true` に収束するべきです

## 送信 RPC

### `send`

ホストのリクエスト:

```json
{
  "jsonrpc": "2.0",
  "id": 5,
  "method": "send",
  "params": {
    "runtime": {
      "name": "whatsapp_web",
      "account_id": "wa-web"
    },
    "message": {
      "target": "room-1",
      "text": "hello",
      "stage": "final",
      "media": []
    }
  }
}
```

必須の成功レスポンス:

```json
{"jsonrpc":"2.0","id":5,"result":{"accepted":true}}
```

プラグインが `capabilities.edit=true` と `capabilities.delete=true` の両方を
アドバタイズしている場合、ホストが後で同じメッセージを更新または削除できるように、
`send` は安定したメッセージ参照を返すこともできます。

```json
{"jsonrpc":"2.0","id":5,"result":{"accepted":true,"message_id":"msg-42"}}
```

または

```json
{"jsonrpc":"2.0","id":5,"result":{"accepted":true,"message":{"target":"room-1","message_id":"msg-42"}}}
```

ルール:

- `message.target` は、プラグインが定義するチャンネルの宛先データです
- `message.text` は常にテキストのフィールド名です。`content` はもう有効ではありません
- `message.stage` は `"final"` または `"chunk"` です
- `message.media` は文字列の配列です
- プラグインが送信を受け付けられない、または受け付けない場合は、成功を偽ってはいけません
- ホスト管理のフォローアップ編集/削除を使用する場合、`message_id` は
  空でない安定したプラットフォーム識別子である必要があります
- `result.message.target` は任意です。省略した場合、ホストは元の
  送信先を再利用します
- `edit` + `delete` をアドバタイズしないプラグインは、
  `{"accepted": true}` のみを返してもかまいません

ホストは現在、次を区別します。

- JSON-RPC の成功: リクエストのトランスポートが完了したこと
- `result.accepted: true`: プラグインが実際にそのアクションを受け付けたこと

`{"accepted": false}` を返すと、成功ではなく拒否されたアクションとして扱われます。

### `send_rich`

`capabilities.send_rich=true` の場合にのみ使用されます。

ホストのリクエスト:

```json
{
  "jsonrpc": "2.0",
  "id": 6,
  "method": "send_rich",
  "params": {
    "runtime": {
      "name": "plugin_chat",
      "account_id": "main"
    },
    "message": {
      "target": "room-1",
      "text": "Choose one",
      "attachments": [
        {
          "kind": "image",
          "target": "/tmp/card.png",
          "caption": "preview"
        }
      ],
      "choices": [
        {
          "id": "yes",
          "label": "Yes",
          "submit_text": "yes"
        }
      ]
    }
  }
}
```

必須の成功レスポンス:

```json
{"jsonrpc":"2.0","id":6,"result":{"accepted":true}}
```

添付ファイルの `kind` の値:

- `image`
- `document`
- `video`
- `audio`
- `voice`

`send_rich` をサポートしていない場合は、ケイパビリティビットを設定しないでください。
ホストは、ペイロードが十分に単純な場合にのみ、通常の `send` にフォールバックすることがあります。

### `edit_message`

`capabilities.edit=true` の場合にのみ使用されます。

ホストのリクエスト:

```json
{
  "jsonrpc": "2.0",
  "id": 7,
  "method": "edit_message",
  "params": {
    "runtime": {
      "name": "plugin_chat",
      "account_id": "main"
    },
    "message": {
      "target": "room-1",
      "message_id": "msg-42",
      "text": "patched",
      "attachments": [],
      "choices": []
    }
  }
}
```

必須の成功レスポンス:

```json
{"jsonrpc":"2.0","id":7,"result":{"accepted":true}}
```

ホストは、ネイティブの `.chunk` ストリーミングをサポートしないチャンネルで、
追跡中の下書きを最新に保つために、先行する `send` の後にこれを使用することがあります。

### `delete_message`

`capabilities.delete=true` の場合にのみ使用されます。

ホストのリクエスト:

```json
{
  "jsonrpc": "2.0",
  "id": 8,
  "method": "delete_message",
  "params": {
    "runtime": {
      "name": "plugin_chat",
      "account_id": "main"
    },
    "message": {
      "target": "room-1",
      "message_id": "msg-42"
    }
  }
}
```

必須の成功レスポンス:

```json
{"jsonrpc":"2.0","id":8,"result":{"accepted":true}}
```

### `set_reaction`

`capabilities.reactions=true` の場合にのみ使用されます。

ホストのリクエスト:

```json
{
  "jsonrpc": "2.0",
  "id": 9,
  "method": "set_reaction",
  "params": {
    "runtime": {
      "name": "plugin_chat",
      "account_id": "main"
    },
    "message": {
      "target": "room-1",
      "message_id": "msg-42",
      "emoji": "✅"
    }
  }
}
```

必須の成功レスポンス:

```json
{"jsonrpc":"2.0","id":9,"result":{"accepted":true}}
```

ルール:

- リアクションを設定/更新するには、`emoji` は文字列である必要があります
- `emoji: null` は、そのメッセージのリアクションをクリアすることを意味します

### `mark_read`

`capabilities.read_receipts=true` の場合にのみ使用されます。

ホストのリクエスト:

```json
{
  "jsonrpc": "2.0",
  "id": 10,
  "method": "mark_read",
  "params": {
    "runtime": {
      "name": "plugin_chat",
      "account_id": "main"
    },
    "message": {
      "target": "room-1",
      "message_id": "msg-42"
    }
  }
}
```

必須の成功レスポンス:

```json
{"jsonrpc":"2.0","id":10,"result":{"accepted":true}}
```

### 入力中表示 RPC

`capabilities.typing=true` の場合にのみ使用されます。

リクエスト:

```json
{"jsonrpc":"2.0","id":11,"method":"start_typing","params":{"runtime":{"name":"plugin_chat","account_id":"main"},"recipient":"room-1"}}
```

```json
{"jsonrpc":"2.0","id":12,"method":"stop_typing","params":{"runtime":{"name":"plugin_chat","account_id":"main"},"recipient":"room-1"}}
```

必須の成功レスポンス:

```json
{"jsonrpc":"2.0","id":13,"result":{"accepted":true}}
```

## 受信通知

プラグインは受信トラフィックを通知として配信します。

```json
{
  "jsonrpc": "2.0",
  "method": "inbound_message",
  "params": {
    "message": {
      "sender_id": "5511",
      "chat_id": "room-1",
      "text": "hello",
      "session_key": "optional-custom-session",
      "media": ["https://example.com/a.jpg"],
      "metadata": {
        "peer_kind": "group",
        "peer_id": "room-1",
        "is_group": true,
        "typing_recipient": "room-1"
      }
    }
  }
}
```

必須フィールド:

- `sender_id`
- `chat_id`
- `text`

任意フィールド:

- `session_key`
- `media`
- `metadata`

検証ルール:

- `sender_id` と `chat_id` は空でない文字列である必要があります
- `text` は文字列である必要があります
- `media` が存在する場合は、空でない文字列の配列である必要があります
- `metadata` が存在する場合は、JSON オブジェクトである必要があります

## メタデータの規約

`metadata` は、チャンネルごとのセマンティクスのための主要な拡張ポイントです。

推奨キー:

- `peer_kind`
  `dm`、`group`、`thread`、またはチャンネル固有の値などの安定したピア種別です。
- `peer_id`
  ルーティング/セッションの分離のために `peer_kind` と組み合わせて使用される安定したピア識別子です。
- `is_group`
  グループであることを明示するヒントです。
- `is_dm`
  ダイレクトメッセージであることを明示するヒントです。
- `typing_recipient`
  入力中インジケーターに使用する宛先識別子です。

ホストの動作:

- ホストは受信メタデータに `account_id` を自動的に注入します
- `session_key` が指定されていない場合、ホストは次から導出します
  - 利用可能な場合は `runtime_name + account_id + peer_kind + peer_id`
  - それ以外の場合は `runtime_name + account_id + chat_id`
- 不明な/外部のチャンネルでは、メタデータは会話コンテキストに昇格されます

## エラーのセマンティクス

次の場合は JSON-RPC の `error` を使用してください。

- 無効なパラメーター
- サポートされていないメソッド
- ブリッジ/トランスポートの障害
- プラグイン内部の障害

`result.accepted: true` は、アクションが実際に受け付けられた場合にのみ使用してください。

推奨される JSON-RPC エラーケース:

- `-32601`
  メソッドが見つからない / 実装されていない
- `-32602`
  無効なパラメーター
- `-32000` 以下
  プラグイン定義のランタイム障害

## タイムアウトと監視

設定された `transport.timeout_ms` は、すべての制御パスですべての呼び出しが
その時間までブロックしてよいことを保証するものではありません。NullClaw は、ヘルスや
監視上重要なリクエストに対して、内部でより厳しい上限を適用します。

運用上の影響:

- ハングしたプラグインがデーモンを永遠にブロックすることはありません
- サポートされていない任意の RPC は学習され、キャッシュされます
- ヘルスの結果は、ホットループでのプローブを避けるために短時間キャッシュされます

それでもプラグインは次のことを守るべきです。

- `stop` に素早く応答する
- stdout をブロックさせない
- 可能な限り、JSON-RPC のメインスレッドで長時間の処理を行わない

QR スキャンやデバイスのリンクなどの対話的な認証フローでは、非同期の
ログインモデルを推奨します。

- `start` はバックグラウンドで接続/認証の処理を開始し、素早く返す
- `health` は、チャンネルがすでに接続済みかつログイン済みかどうかを報告する
- ホストのコントロールプレーンのタイムアウトを引き延ばすのではなく、プラグインまたは
  付随するブリッジが QR の描画 / ペアリングの UX を担う

## セキュリティと分離

ホストの境界は意図的に狭くしていますが、プラグインのコードは依然として nullclaw ユーザーの
権限を持つローカルプロセスとして実行されます。

推奨事項:

- プラグインは、サンドボックス化された信頼できないコードではなく、信頼できるローカルソフトウェアとして扱う
- ブリッジの URL はローカルまたは HTTPS にする
- シークレットは `transport.env` またはプラグインローカルの設定を通じて慎重に渡す
- トークンや生のユーザーコンテンツを stderr にログ出力しない
- プラグインの状態は `runtime.state_dir` の下にのみ保存する

## CLI と運用

便利なコマンド:

```bash
nullclaw channel start external
```

設定済みの最初の外部アカウントを起動します。

```bash
nullclaw channel start whatsapp_web
```

ランタイム名が `whatsapp_web` の設定済み外部アカウントを起動します。

## リファレンスアダプター

リポジトリには次の場所にブリッジアダプターが含まれています。

- [`examples/whatsapp-web/nullclaw-plugin-whatsapp-web`](../../examples/whatsapp-web/nullclaw-plugin-whatsapp-web)
- [`examples/external-channel-template/nullclaw-plugin-template`](../../examples/external-channel-template/nullclaw-plugin-template)

これは、PR #265 の WhatsApp Web HTTP ブリッジの形式を、現在の
ExternalChannel JSON-RPC 契約に変換するものです。

ブリッジの認証と WhatsApp の認証の違い、QR/ペアリングの担当、初回実行時の検証を含む、
WhatsApp Web のオペレーター向けの手順全体については、サンプルの README を参照してください。

- [`examples/whatsapp-web/README.md`](../../examples/whatsapp-web/README.md)

WhatsApp 固有のブリッジではなく、汎用的なプラグイン作成の出発点が必要な場合は、
次を使用してください。

- [`examples/external-channel-template/README.md`](../../examples/external-channel-template/README.md)

ツリー外の関連リポジトリ:

- [nullclaw/nullclaw-channel-baileys](https://github.com/nullclaw/nullclaw-channel-baileys)
  QR およびペアリングコードのフローを備えた、Node/Baileys を直接使う外部チャンネルプラグインです。
- [nullclaw/nullclaw-channel-whatsmeow-bridge](https://github.com/nullclaw/nullclaw-channel-whatsmeow-bridge)
  QR、ペアリングコード、デプロイ用アセットを備えた、スタンドアロンの Go/whatsmeow HTTP ブリッジです。
- `nullclaw-channel-imap-connector`
  双方向のメールと、付随するメールボックス CLI ワークフローのための、
  Python 製 IMAP/SMTP 外部チャンネルプラグインです。

本番運用向けのチャンネル固有のコードは、これらのリポジトリに置くことを推奨します。
ここにあるツリー内のサンプルは、リファレンスアダプターおよびテンプレートです。

## プラグイン作成者向けチェックリスト

- `get_manifest` を実装する
- `start`、`send`、`stop` を実装する
- `protocol_version: 2` を返す
- `start` から `started: true` を返す
- QR スキャン、ペアリング、対話的な認証に関して `start` をノンブロッキングに保つ
- 受け付けた送信アクションからは `accepted: true` を返す
- `content` ではなく `text` を使って `inbound_message` を発行する
- ピアのルーティングが重要な場合は、メタデータに `peer_kind` と `peer_id` を含める
- 永続的なアカウント状態には `state_dir` を使用する
- stdout をプロトコル以外の出力で汚さない

## トラブルシューティング

`channel start <runtime_name>` が即座に失敗する:

- `transport.command` を確認する
- マニフェストが `protocol_version: 2` を使用していることを確認する
- `start.result.started` が存在し、true であることを確認する

メッセージが正しいセッションに届かない:

- `session_key`、または少なくとも `metadata.peer_kind` と `metadata.peer_id` を含める
- 複数のアカウントが同じ `runtime_name` を再利用していないことを確認する

実際のブリッジが停止しているのにヘルスが正常に見える:

- `health` を実装する
- レスポンスが意味のあるものでない限り、`capabilities.health=true` をアドバタイズしない

プラグインのログがホストを壊す:

- stdout には JSON-RPC のみを含める必要があります
- 人間が読むためのログは代わりに stderr に送る
