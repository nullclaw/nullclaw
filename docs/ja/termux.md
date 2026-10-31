# Termux ガイド

このガイドでは、Android / Termux で NullClaw を使うための実践的な手順を説明します。

## このページのガイド

**このページの対象読者**

- Termux 内で NullClaw を直接実行している Android ユーザー
- モバイルへのインストールについてドキュメントを書いたりトラブルシューティングしたりするコントリビューター
- 自分のワークロードに Termux で十分かどうかを判断するオペレーター

**次に読むページ**

- まずインストール方法の全体像を知りたい場合は[インストール](./installation.md)を開いてください
- バイナリが動作したら[設定](./configuration.md)を開いてください
- `agent` や `gateway` をテストする準備ができたら[使い方と運用](./usage.md)を開いてください

## 想定される使い方

Termux が最も適しているのは次の用途です:

- フォアグラウンドでの使用
- 手動テスト
- 制約のあるローカルデプロイ

Termux があまり適していないのは次の用途です:

- スマートフォン自体での長時間にわたる重い推論
- Android のプロセス圧迫に耐えて存続する必要がある、サービス形式のバックグラウンド運用

メモリ不足により Android がプロセスを終了させた場合、それは Android / Termux の制約であり、必ずしも NullClaw のバグではありません。

## 前提条件

- **Zig 0.16.0(厳密にこのバージョン)**
- Git
- リポジトリとビルドキャッシュを置くのに十分なローカルストレージ

ビルドする前に Zig を確認してください:

```bash
zig version
```

出力は `0.16.0` でなければなりません。

## Termux でのネイティブビルド

```bash
pkg update
pkg install git zig
git clone https://github.com/nullclaw/nullclaw.git
cd nullclaw
zig version
zig build -Doptimize=ReleaseSmall
./zig-out/bin/nullclaw --help
```

補足:

- Termux でのネイティブビルドでは、通常 `-Dtarget` は**不要**です。
- `-Doptimize=ReleaseSmall` または `-Doptimize=ReleaseFast` を推奨します。
- 古い例にある、以前の `-Drelease-fast` 構文は使用**しないでください**。

## 依存関係を減らしたビルド

Termux で SQLite の取得やビルドの手順が失敗する場合は、まずより軽量なエンジンセットを試してください:

```bash
zig build -Doptimize=ReleaseSmall -Dengines=base
```

`-Dengines=base` は `markdown,memory,api,none` を残し、SQLite を使用しません。

エンジンを明示的に選ぶこともできます:

```bash
zig build -Doptimize=ReleaseSmall -Dengines=markdown,memory
```

小さめの Android デバイスでは、これが最初の目標として最適なことがよくあります。

## よくある失敗: `build.zig.zon` "expected string literal"

次のようなエラーが表示された場合:

```text
build.zig.zon:2:14: error: expected string literal
```

通常の原因は Zig のバージョンが間違っていることであり、NullClaw のソースツリーではありません。

チェックリスト:

1. `zig version` を実行します。
2. `0.16.0` と表示されることを確認します。
3. 表示されない場合は、再試行する前に Zig のパッケージまたはバイナリを入れ替えます。

古い Zig ビルドに対処するために、`build.zig.zon` をローカルでパッチしないでください。このプロジェクトは Zig 0.16.0 に固定されています。

## 初回の実行時チェック

バイナリがビルドできたら、まず最もシンプルな 2 つのエントリーポイントを確認してください:

```bash
./zig-out/bin/nullclaw agent
./zig-out/bin/nullclaw gateway --host 127.0.0.1 --port 3001
```

ラッパー、ランチャー、バックグラウンドでの自動化を試す前に、まずフォアグラウンドでの実行から始めてください。

## Android 向けのクロスコンパイル

別のマシンで Termux / Android デバイス向けにビルドする場合は、Zig のターゲットと Android の libc/sysroot ファイルの両方が必要です:

```bash
zig build -Dtarget=aarch64-linux-android.24 -Doptimize=ReleaseSmall --libc /path/to/android-libc-aarch64.txt
```

よく使うターゲット:

- `aarch64-linux-android.24`
- `-Dcpu=baseline+v7a` を指定した `arm-linux-androideabi.24`
- `x86_64-linux-android.24`

デバイスのアーキテクチャに合ったターゲットを使用してください。
Android NDK から `--libc` ファイルを生成する完全な例については、[`.github/workflows/release.yml`](../../.github/workflows/release.yml) を参照してください。

## 実践的なアドバイス

- 最初の目標は小さく保ってください: バイナリをビルドし、`--help` を実行してから、`agent` または `gateway` を実行します。
- デバイスの RAM が限られている場合は、まずリモートのモデルプロバイダーを優先してください。
- 長時間安定して動作するワークロードが必要な場合、Termux は最終的なホストというよりもテスト環境と考えるのがよいかもしれません。

## 関連ページ

- [インストール](./installation.md)
- [設定](./configuration.md)
- [使い方と運用](./usage.md)
- [コマンド](./commands.md)
