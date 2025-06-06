# 解析レポート

![中高信頼度](https://img.shields.io/badge/信頼度-中高-orange) **信頼度スコア: 70**

## 脆弱性タイプ

- `SQLI`
- `IDOR`

## 解析結果

以下のコードから、主に以下の重大な脆弱性を確認しました。

1. SQLインジェクション (/api/v1/db/query)
   ユーザー提供のクエリ文字列をそのまま実行しており、パラメータのサニタイズも行われていません。悪意ある入力で任意のSQLを実行可能です。

2. 不適切な認可制御（IDOR 相当）
   認証・認可チェックなしに暗号化サービスやバリデーションサービス、直接DBアクセス API を公開しており、誰でも任意の操作が可能です。

3. 詳細なエラー情報漏洩
   例外ハンドラ (/setupErrorHandling) でスタックトレースやリクエストヘッダーをクライアントに返却しており、内部構造や環境変数を漏洩します。

4. CORS 設定の過度な許可
   origin: true, allowedHeaders: ['*'] としており、任意のオリジンから CSRF/情報窃取リクエストが行えます。

これらにより、データベースの完全破壊や認可回避、内部情報漏洩を許してしまいます。修正の際はプリペアドステートメントによるクエリ実行、認可チェックの追加、エラー情報の抑制および最小限の CORS 設定を行ってください。

## PoC（概念実証コード）

```text
// SQLインジェクションのPOC
curl -X POST http://localhost:3000/api/v1/db/query \
  -H 'Content-Type: application/json' \
  -d '{"query":"SELECT * FROM users WHERE username = 'admin' OR '1'='1'--","params":[]}';

// 任意エンドポイントへの無認証アクセス（IDOR）
curl http://localhost:3000/api/v1/services/encryption/demo?action=encrypt&data=secret
```

## 関連コードコンテキスト

### 関数名: /api/v1/db/query
- 理由: ユーザー入力のSQLクエリをそのまま実行しており、SQLインジェクションが可能
- パス: app-clean.js
```rust
this.app.post('/api/v1/db/query', async (req, res) => { const { query, params } = req.body; const result = await this.userRepository.executeQuery(query, params); ... });
```

### 関数名: /api/v1/services/encryption/demo
- 理由: 認可チェックなしで暗号化機能を提供しており、IDOR相当の不正アクセスを許可
- パス: app-clean.js
```rust
this.app.get('/api/v1/services/encryption/demo', (req, res) => { const { action, data } = req.query; ... });
```

## 解析ノート

大量のエンドポイントをスキャンし、特に外部入力を内部関数に渡している箇所を重点的に確認。直接DBクエリ実行部と認可レスなサービス公開部が致命的。

