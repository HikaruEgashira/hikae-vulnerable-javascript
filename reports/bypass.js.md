# 解析レポート

![中高信頼度](https://img.shields.io/badge/信頼度-中高-orange) **信頼度スコア: 85**

## 脆弱性タイプ

- `XSS`
- `SQLI`
- `RCE`
- `LFI`
- `AFO`

## 解析結果

本コードには複数の入力バリデーション不備があり、各種バイパステクニックを容易に悪用できます。

1. XSS (/xss/filter-test)  ユーザー入力を不完全にブラックリスト／エスケープしており、HTMLコンテキスト／JavaScriptコンテキストに生の入力を埋め込んでいます。
2. SQLインジェクション (/sql/filter-test)  シンプルなシングルクォートエスケープと部分的なキーワード除去のみで、ワイルドカード的な構文変形や大文字小文字のバイパスで容易にインジェクション可能です。
3. コマンドインジェクション (/command/bypass-test)  危険文字を正規表現で除去するだけで、独自セパレータやエンコーディングで注入可能な `execSync` 呼び出しがあります。
4. パストラバーサル (/path/traversal-test)  「..」の単純除去と固定文字列置換のみで、二重エンコーディングやワイルドカードで `/safe/uploads/` 以外のファイルを読み取れます。
5. 認証バイパス (/auth/bypass-demo)  デバッグモードフラグや固定adminKey、空パスワード、弱いJWT検証など、多重の認証バイパスロジックが存在します。
6. ファイルタイプバイパス (/file/type-bypass)  拡張子の最後のみチェック、MIMEチェックも任意で不十分なため、複数拡張子やヌルバイト挿入で任意のファイルをアップロードできます。

これらはすべて実際に攻撃者がリモートで悪用可能な深刻な脆弱性です。

## PoC（概念実証コード）

```text
【コマンドインジェクションの PoC 】
curl -X POST http://<host>/bypass/command/bypass-test \
  -H 'Content-Type: application/json' \
  -d '{"command":"echo test; uname -a"}'

→ フィルタをバイパスしてサーバーのOS情報を取得可能
```

## 関連コードコンテキスト

### 関数名: /xss/filter-test
- 理由: ユーザー入力をHTMLコンテキストに出力し、エスケープが不完全なためXSS可能
- パス: ./routes/bypass.js
```rust
<p>Rendered: <div>${input}</div></p>
```

### 関数名: /xss/filter-test
- 理由: JavaScript文字列内に直接生の入力を埋め込んでおりXSSリスクがある
- パス: ./routes/bypass.js
```rust
const userInput = '${input.replace(/'/g, "\'")}'
```

### 関数名: /sql/filter-test
- 理由: 部分的なクォートエスケープのみで完全なSQLインジェクション対策になっていない
- パス: ./routes/bypass.js
```rust
const query = `SELECT * FROM users WHERE username = '${filteredUsername}' AND password = '${filteredPassword}'`
```

### 関数名: /command/bypass-test
- 理由: 正規表現による文字削除だけでexecSyncに任意コマンドを注入可能
- パス: ./routes/bypass.js
```rust
const output = execSync(fullCommand, { encoding: 'utf8', timeout: 3000 })
```

### 関数名: /path/traversal-test
- 理由: 「..」だけを除去するフィルタではバイパスが可能なパストラバーサル脆弱性
- パス: ./routes/bypass.js
```rust
const fullPath = path.join('/safe/uploads/', filtered)
```

### 関数名: /file/type-bypass
- 理由: 拡張子の末尾だけ検証しており、二重拡張子やヌルバイトを使ったバイパスが可能
- パス: ./routes/bypass.js
```rust
const isAllowedExt = allowedExtensions.includes(fileExt)
```

### 関数名: /auth/bypass-demo
- 理由: デバッグモードフラグによる即時認証バイパスが可能
- パス: ./routes/bypass.js
```rust
if (debugMode === 'true' || debugMode === '1')
```

## 解析ノート

XSS: HTML/JSコンテキストにエスケープ不備
SQLi: クォート＆キーワード除去だけで不十分
RCE: execSync に任意文字を注入
LFI: ..の単純除去でバイパス
ファイルアップロード: 拡張子チェック甘い
Auth: debug/adminKey/empty-pass/JWT弱検証

