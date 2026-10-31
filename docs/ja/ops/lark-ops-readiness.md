# Lark 運用準備

このガイドでは、Lark/Feishu に固有のチャンネル運用チェックを定義します。

## ヘルスの意味

- Websocket モードは、running と connected の両方が true の場合にのみ正常です。
- Webhook モードは、ランタイムがアクティブで、コールバックパスに到達可能な場合に正常です。

## 認証と権限

1. テナントトークンの取得とリフレッシュの動作を検証します。
2. 0 以外のビジネスコードは運用上の障害として扱います。
3. 権限/スコープに関連するようなエラーは、直ちにエスカレーションします。

## `error.LarkApiError` の迅速なトリアージ

1. `nullclaw doctor` を実行して、チャンネル設定が構造的に有効であることを確認します。
2. 起動後に `nullclaw channel status` を実行して、チャンネルが実行中なのに切断されている状態かどうかを確認します。
3. `warning(lark): lark websocket cycle failed: error.LarkApiError` が繰り返し出る場合は、次のいずれかとして扱います。
   - Lark/Feishu アプリの権限またはスコープの不足
   - リージョンエンドポイントの選択ミス（`use_feishu`）
   - websocket コールバックのプロビジョニング失敗
4. 古い Linux ビルドが安定した再接続ログを出す前にクラッシュする場合は、まずアップグレードしてから権限のトリアージを続けます。

## インシデント対応手順

1. Feishu/Lark コンソールでアプリの権限/スコープを確認します。
2. コールバックエンドポイントと websocket パスが利用可能であることを検証します。
3. 送信者の許可リスト（`allow_from`）とグループでのメンションの動作を確認します。
4. チャンネルワーカーの再起動は、根本原因を把握してから行います。

## SLO シグナル

- auth_fail_total
- reconnect_total
- outbound_send_fail_total
- healthcheck_fail_total
