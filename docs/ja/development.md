# 開発

このページはコントリビューター向けです。リポジトリのセットアップ、焦点を絞った変更、その検証、そして PR の作成までを、迷うことなく進められるようにすることを目的としています。

## このページのガイド

**このページの対象読者**

- ローカルの開発環境を準備しているコントリビューター
- PR を作成またはレビューする前に変更を検証するメンテナー
- リポジトリのワークフローと検証の基準を確認するドキュメントやコードの作成者

**次に読むページ**

- 慣れていないサブシステムに手を入れる前に[アーキテクチャ](./architecture.md)を開いてください
- 変更が CLI の動作やドキュメントに影響する場合は[コマンド](./commands.md)を開いてください
- より広いドキュメントマップが必要な場合は [README](./README.md) を開いてください

**以下のページから来た場合**

- [README](./README.md): このページでは、コントリビューター固有のセットアップと検証に道筋を絞り込みます
- [コマンド](./commands.md): CLI の変更にワークフロー、テスト、PR に関するガイダンスも必要な場合は、ここに来てください
- `AGENTS.md`: 日々のコントリビューションにおける実践的なチェックリストとして、このページを使ってください

## 編集を始める前に

- 開発とテストは **Zig 0.16.0** に固定されています。Debian で Zig が必要な場合は、[Zig のインストール](./zig-installation.md)を参照してください。
- コードを変更する前に `AGENTS.md` を読んでください。
- プロジェクトのより詳しいコンテキスト、検証ルール、サブシステムに関するガイダンスが必要な場合は `CLAUDE.md` を読んでください。
- リポジトリの flake を使用する場合、`nix build` と `nix develop` はどちらも **Zig 0.16.0** に固定されています。

まず Zig のバージョンを確認してください:

```bash
zig version
```

## ローカルでのビルドとテスト

```bash
zig build
zig build -Doptimize=ReleaseSmall
zig build test --summary all
```

コードの変更について PR を作成する前に、最低限これを実行してください:

```bash
zig build test --summary all
```

## よく使うビルドフラグ

```bash
zig build -Dchannels=telegram,cli
zig build -Dengines=base,sqlite
zig build -Dtarget=x86_64-linux-musl
zig build -Dversion=2026.3.1
```

補足:

- `channels`: コンパイルに含めるチャンネル実装を制限します
- `engines`: ビルドに含めるメモリエンジンを制限します
- `target`: クロスコンパイルのターゲットトリプル
- `version`: 埋め込まれるバージョン文字列を上書きします(デフォルトは `dev`。リリースワークフローでは git タグが注入されます)

## 推奨ワークフロー

1. まず対象のモジュールと近くにあるテストを読みます。
2. 各 PR は 1 つの関心事に絞ります。
3. 同じ変更の一部としてドキュメントとテストを更新します。
4. PR を作成する前に検証します。

## ドキュメントの同期

変更がユーザー、オペレーター、コントリビューターに影響する場合は、同じ PR で関連するドキュメントを更新してください:

- ランディングページ: `README.md`
- 英語ドキュメント: `docs/en/`
- 中国語ドキュメント: `docs/zh/`
- セキュリティポリシー: `SECURITY.md`
- 専門的なデプロイガイド: `SIGNAL.md`
- コントリビューションガイド: `CONTRIBUTING.md`

ドキュメントは次の状態を保つ必要があります:

- タスク指向であること
- コピー＆ペーストしやすいこと
- `src/main.zig` および現在の設定スキーマと一貫していること
- 英語と中国語の両方の読者に影響する場合は、両言語間で同期されていること

## Git フック

クローンごとに一度、リポジトリのフックを有効にしてください:

```bash
git config core.hooksPath .githooks
```

含まれるフック:

- `pre-commit` は `zig fmt --check src/` を実行します
- `pre-push` は `zig build test --summary all` を実行します

## PR 前の検証

### ドキュメントのみの変更

推奨:

```bash
git diff --check
```

リンク、パス、コマンド例も手動で確認してください。

### コードの変更

必須:

```bash
zig build test --summary all
```

### リリースに影響する変更

次も実行してください:

```bash
zig build -Doptimize=ReleaseSmall
```

## PR のガイダンス

PR の説明では、次の内容を説明してください:

1. 何を変更したか
2. なぜ変更したか
3. どのような検証を実行したか
4. リスクやフォローアップ作業があればその内容

推奨テンプレート:

```text
## Summary
- ...

## Validation
- zig build test --summary all

## Notes
- ...
```

## よく触るパス

| パス | 用途 |
|---|---|
| `src/main.zig` | CLI コマンドのルーティング |
| `src/config.zig` | 設定の読み込みと環境変数による上書き |
| `src/gateway.zig` | ゲートウェイと Webhook |
| `src/security/` | セキュリティとサンドボックス |
| `src/providers/` | モデルプロバイダー |
| `src/channels/` | メッセージングチャンネル |
| `src/tools/` | ツールの実装 |
| `src/memory/` | メモリバックエンドと検索 |

## 関連資料

- アーキテクチャ: `docs/en/architecture.md`
- コマンド: `docs/en/commands.md`
- コントリビューションガイド: `CONTRIBUTING.md`
- エンジニアリングプロトコル: `AGENTS.md`

## 次のステップ

- ランタイム、セキュリティ、プロバイダーのより深い部分のコードを編集する前に[アーキテクチャ](./architecture.md)を読んでください
- 変更が CLI のインターフェースや例に関わる場合は[コマンド](./commands.md)を利用してください
- 最終的な PR の説明とレビューの流れを準備する前に [CONTRIBUTING.md](../../CONTRIBUTING.md) を開いてください

## 関連ページ

- [README](./README.md)
- [インストール](./installation.md)
- [設定](./configuration.md)
- [コマンド](./commands.md)
