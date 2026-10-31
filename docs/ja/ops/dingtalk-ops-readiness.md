# DingTalk 運用準備

このページでは、DingTalk 固有の検証と、メッセージの送信はできるのに受信イベントを
受け取れないランタイムを最短でデバッグする方法を説明します。

## ページガイド

**このページの対象読者**

- 新しい DingTalk デプロイメントを検証するオペレーター
- 受信メッセージの欠落やチャンネルステータスの異常を診断するトラブルシューター
- 報告された問題が設定のずれ、古いバイナリ、または DingTalk 側の配信問題のどれに
  あたるかを確認するメンテナー

**次に読むもの**

- 一般的なサービスとログの流れについては [使い方と運用](../usage.md) を開いてください
- メインの設定ファイルの背景については [設定](../configuration.md) を開いてください
- `allow_from` を広げる前に [セキュリティ](../security.md) を開いてください

## 正常な状態とは

- 現在のビルドでは、DingTalk はゲートウェイループのチャンネルとして起動します。起動ログでは
  `dingtalk started (send-only)` ではなく `dingtalk gateway started` と表示されます。
- チャンネルのヘルスが true になるのは、ランタイムが実行中で、かつ DingTalk の
  stream websocket が接続されている場合のみです。
- 受信の配信が壊れていても、新しいセッション webhook ターゲット経由で送信の返信が
  成功することがあります。そのため「送信はできるが受信できない」場合、通常は返信パスではなく
  stream パスに原因があります。

## 事前チェックリスト

1. 現在のビルドを実行していることを確認します。ログにまだ
   `dingtalk started (send-only)` と表示される場合は、まずアップデートしてください。
2. `channels.dingtalk.accounts.<id>.client_id` と `client_secret` が
   同じ DingTalk アプリのものであることを確認します。
3. `allow_from` が空でないことを確認します。`allow_from: []` はすべての受信
   メッセージを拒否します。
4. `nullclaw gateway` でランタイムを起動し、
   `nullclaw channel status` で DingTalk が正常と表示されることを確認します。
5. 認証情報が疑わしい場合は、
   `nullclaw --probe-channel-health --channel dingtalk --account <id>` を実行して
   トークンの取得を検証します。

## 受信メッセージがまったく届かない場合

1. DingTalk アプリが stream モードでの受信配信用に設定されていることを確認します。
   現在のランタイムは DingTalk のゲートウェイ接続 API 経由で websocket を開くため、
   送信専用のセットアップでは不十分です。
2. アプリが受信したいメッセージイベントをサブスクライブしていることを確認します。
   DingTalk がそれらのコールバックを一切発行しない場合、nullclaw が取り込むものはありません。
3. フォアグラウンドで実行し、再起動する前に最初の DingTalk エラーを記録します。
   最も重要なログ行は `dingtalk websocket cycle failed`、
   `dingtalk websocket read failed`、
   `dingtalk envelope handling failed` です。
4. `allow_from` に明示的に含まれている送信者で再テストします。
   許可リストに一致しない場合は、トランスポートの障害ではなく「message ignored」のように見えます。

## 返信ターゲットとフォールバックの動作

- 新しい返信ターゲットは、受信イベントに付与された `sessionWebhook` URL を使用します。
- グループの返信ターゲットが期限切れになった場合、nullclaw はキャッシュされた会話 ID を使って
  DingTalk AI インタラクション API にフォールバックできます。
- ダイレクトメッセージの返信ターゲットにはそのグループ用フォールバックがありません。セッション
  webhook が期限切れになると、新しい受信イベントかプロアクティブなターゲットが必要になります。
- 任意の `https://...` webhook ターゲットは意図的に拒否されます。また、メディア
  ペイロードは現在、送信ではサポートされていません。

## 推奨される検証手順

```bash
nullclaw doctor
nullclaw status
nullclaw channel status
nullclaw gateway
```

その後、許可された送信者から DingTalk メッセージを送り、何かを再起動する前に
最初のランタイムエラーを確認してください。
