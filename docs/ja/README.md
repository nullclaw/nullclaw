# NullClaw 日本語ドキュメント

このディレクトリでは、NullClaw の体系的な日本語ドキュメントを提供しています。インストール、設定、運用、連携、開発までを扱います。

コミュニティ: [Discord に参加する](https://discord.gg/Bfmdua22Ud)

初めての方は、最初にどのページを開くべきか迷う代わりに、以下のガイド付きの道筋を利用してください。

## このページのガイド

**このページの対象読者**

- 最初に読むドキュメントの道筋を選んでいる新規ユーザー
- 次にどの運用ガイドを開くべきか判断しているオペレーター
- より詳しいドキュメントに進む前に適切な入口を探しているコントリビューター

**次に読むページ**

- NullClaw がまだ動いていない場合は、[インストール](./installation.md)から始めてください
- Debian でのソースビルドに先立って Zig が必要な場合は、[Zig のインストール](./zig-installation.md)を参照してください
- すでにインストール済みの場合は、[設定](./configuration.md)に進んでください
- タスク別の CLI リファレンスが必要な場合は、[コマンド](./commands.md)に移動してください

**以下のページから来た場合**

- `README.md`: このページを日本語のランディングページとして使い、必要なガイドへ進んでください
- [コマンド](./commands.md): ドキュメント全体のより広いマップが必要な場合は、ここに戻ってきてください
- [開発](./development.md): コントリビューター向けワークフロー以外のユーザー向け・オペレーター向けドキュメントが必要な場合は、ここに戻ってきてください

## 目的別の道筋

TH:### 0. 技術的な知識がない場合
JQ:
NP:AI モデルを設定したことがない、JSON ファイルを編集したことがない、またはコマンドラインツールを使ったことがない場合は、ここから始めてください。
VB:
BV:[初心者ガイド](./beginners-guide.md)
VX:
MS:
TH:### 1. とにかく動かしたい場合
JQ:
NP:推奨する順序:
WV:
WJ:1. [インストール](./installation.md)
QJ:2. [設定](./configuration.md)
HS:3. [使い方と運用](./usage.md)
HZ:4. [コマンド](./commands.md)
MS:
### 2. デプロイや運用のガイダンスが必要な場合

重点的に読むページ:

- [使い方と運用](./usage.md)
- [セキュリティ](./security.md)
- [Gateway API](./gateway-api.md)
- [DingTalk 運用準備](./ops/dingtalk-ops-readiness.md)
- [Lark 運用準備](./ops/lark-ops-readiness.md)
- [Signal のデプロイ](../../SIGNAL.md)

### 3. 組み込みチャンネル以外とも連携したい場合

重点的に読むページ:

- [外部チャンネルプラグイン](./external-channels.md)
- [設定](./configuration.md)
- [使い方と運用](./usage.md)
- [アーキテクチャ](./architecture.md)

### 4. コードやドキュメントに貢献したい場合

重点的に読むページ:

- [アーキテクチャ](./architecture.md)
- [開発](./development.md)
- [コマンド](./commands.md)
- [コントリビューション](../../CONTRIBUTING.md)

## ナビゲーション

QV:- [初心者ガイド](./beginners-guide.md)  ← NullClaw を初めて使う場合はここから始めてください
- [インストール](./installation.md)
- [Zig のインストール](./zig-installation.md)
- [Termux ガイド](./termux.md)
- [設定](./configuration.md)
- [使い方と運用](./usage.md)
- [アーキテクチャ](./architecture.md)
- [セキュリティ](./security.md)
- [Gateway API](./gateway-api.md)
- [外部チャンネルプラグイン](./external-channels.md)
- [コマンド](./commands.md)
- [開発](./development.md)

## 運用ランブック

- [DingTalk 運用準備](./ops/dingtalk-ops-readiness.md)
- [Lark 運用準備](./ops/lark-ops-readiness.md)

## まずはここから

1. NullClaw は現在 **Zig 0.16.0**(厳密なバージョン指定)を必要とします。Debian でのセットアップは [Zig のインストール](./zig-installation.md)で説明しています。
2. デフォルトの設定パスは `~/.nullclaw/config.json` です(`nullclaw onboard` によって生成されます)。
3. 初回実行時は `onboard --interactive` を使い、その後 `agent` と `gateway` で動作を確認してください。

## 最速の初回実行(3 分)

```bash
brew install nullclaw
nullclaw onboard --interactive
nullclaw agent -m "hello nullclaw"
```

Homebrew でインストールしない場合は、コンテナやソースからの手順について[インストール](./installation.md)から始めてください。

## 専門ガイド

- [コントリビューション](../../CONTRIBUTING.md)
- [セキュリティポリシー](../../SECURITY.md)
- [Signal のデプロイ](../../SIGNAL.md)

## 次のステップ

- Homebrew、コンテナ、ソースからのセットアップについては[インストール](./installation.md)に従ってください
- プロバイダー、メモリ、チャンネル、ゲートウェイの設定を構成するには[設定](./configuration.md)に進んでください
- NullClaw を日常的に運用したくなったら[使い方と運用](./usage.md)を利用してください

## 関連ページ

- [Termux ガイド](./termux.md)
- [コマンド](./commands.md)
- [開発](./development.md)
- [アーキテクチャ](./architecture.md)
- [Gateway API](./gateway-api.md)
