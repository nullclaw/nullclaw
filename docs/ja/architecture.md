# アーキテクチャ

NullClaw は、vtable 駆動のプラガブルなアーキテクチャを採用しています。ほとんどの機能は、インターフェースを実装してファクトリーを登録することで拡張できます。

## ページガイド

**このページの対象読者**

- コードを編集する前に主要なサブシステムの境界を学びたいコントリビューター
- 変更が vtable とファクトリーによる拡張モデルに従っているかを確認するレビュアー
- 新しいプロバイダー、チャンネル、ツール、メモリバックエンド、ランタイムをどこに組み込むかを判断するインテグレーター

**次に読むページ**

- リポジトリに変更を加えたり、コントリビューター向けの検証フローを実行したりする前に [開発](./development.md) を開いてください
- 設計がゲートウェイ、サンドボックス、ツール、または公開範囲の境界に関わる場合は [セキュリティ](./security.md) を開いてください
- このコントリビューター向けのビューを取り巻く、より広い英語ドキュメントの全体像が必要な場合は [README](./README.md) を開いてください

**以下のページから来た場合**

- [開発](./development.md): このページは、コントリビューターのワークフローの背後にあるサブシステムの全体像を示します
- [README](./README.md): 実装レベルのコンテキストが必要だとわかったら、ここがより深い設計への入口です
- `AGENTS.md`: このページを使って、リポジトリのガードレールと具体的なモジュール構成や拡張ポイントを結び付けてください

## コア設計

- サブシステムは `ptr: *anyopaque + vtable` を用いたインターフェースによって抽象化されています。
- ランタイムの実装はファクトリーを通じて選択されます。
- プロバイダー/チャンネル/ツール/メモリの差し替えに、コアのオーケストレーションの書き換えを必要とするべきではありません。

## サブシステムと拡張ポイント

| サブシステム | インターフェース | 組み込み実装（一部） | 拡張方法 |
|---|---|---|---|
| AI モデル | `Provider` | OpenRouter、Anthropic、OpenAI、Azure OpenAI、Gemini、Vertex AI、Ollama、Groq、Mistral、xAI、DeepSeek、Together、Fireworks、Perplexity、Cohere、Bedrock、Venice、NEAR AI Cloud、Atlas Cloud、Evolink、Eden AI、および多数の OpenAI 互換エンドポイント | プロバイダー実装を追加して登録 |
| チャンネル | `Channel` | CLI、Telegram、Signal、Discord、Slack、Matrix、WhatsApp、Nostr、IRC、Lark、Line、DingTalk、Email、OneBot、QQ、MaixCam、Mattermost、iMessage、Web、Teams、Max | チャンネル実装を追加して登録 |
| メモリ | `Memory` | SQLite（ハイブリッド検索）、Markdown、ClickHouse、PostgreSQL、Redis、LanceDB、Lucid、LRU、API、None | メモリバックエンドを追加 |
| ツール | `Tool` | shell、file_read、file_write、file_edit、file_edit_hashed、file_read_hashed、file_append、http_request、web_fetch、web_search、delegate、screenshot、browser_open、ほか 20 以上 | ツール実装を追加 |
| オブザーバビリティ | `Observer` | Noop、Log、File、Multi | オブザーバーバックエンドを追加 |
| ランタイム | `RuntimeAdapter` | Native、Docker、WASM | ランタイムアダプターを追加 |
| セキュリティ | `Sandbox` | Landlock、Firejail、Bubblewrap、Docker（自動） | サンドボックスバックエンドを追加 |
| トンネル | `Tunnel` | None、Cloudflare、Tailscale、ngrok、Custom | トンネルプロバイダーを追加 |
| 周辺機器 | `Peripheral` | Serial、Arduino、RPi GPIO、STM32/Nucleo | ハードウェアドライバーを追加 |

## メモリスタック

| レイヤー | 実装 |
|---|---|
| ベクトル検索 | SQLite に BLOB として格納した埋め込み、コサイン類似度検索 |
| キーワード検索 | BM25 を用いた SQLite FTS5 |
| ハイブリッドマージ | ベクトルとキーワードの重み付きマージ |
| 埋め込み | `EmbeddingProvider` vtable（OpenAI/カスタム/noop） |
| データ衛生 | 自動アーカイブと削除 |
| スナップショット | 完全なエクスポート/インポートによる移行パス |
| エンジン | SQLite（デフォルト）、Markdown、ClickHouse、PostgreSQL、Redis、LanceDB、Lucid、LRU、API、None |

## 実践上の制約

1. コアへの侵襲的な書き換えではなく、実装による拡張を優先してください。
2. サブシステムの境界を厳格に保ってください（サブシステムをまたいだ内部実装の結合を避けてください）。
3. 高リスクなパス（`security/runtime/gateway/tools`）では、境界および障害パスの検証を含めてください。

## 次のステップ

- コントリビューターのワークフロー、検証で求められること、PR の準備については [開発](./development.md) を読んでください
- このページで挙げた高リスクなサブシステムを変更する前に [セキュリティ](./security.md) を確認してください
- この設計概要を読んだ後で、より広いドキュメントの全体像を見たい場合は [README](./README.md) に戻ってください

## 関連ページ

- [README](./README.md)
- [開発](./development.md)
- [セキュリティ](./security.md)
- [コマンド](./commands.md)
