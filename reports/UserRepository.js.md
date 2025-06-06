# 解析レポート

![高信頼度](https://img.shields.io/badge/信頼度-高-red) **信頼度スコア: 90**

## 脆弱性タイプ

- `SQLI`

## 解析結果

UserRepository クラスの各メソッドで、文字列連結やテンプレートリテラルを用いて外部からの入力を直接 SQL クエリに埋め込んでおり、SQL インジェクション攻撃が可能です。特に findById, findByUsername, findByEmail, findAll, create, update, delete, authenticate, search, executeQuery の各メソッドはプレースホルダやサニタイズを一切行わずにパラメータを利用しているため、悪意のある入力により任意の SQL を実行される恐れがあります。

## PoC（概念実証コード）

```text
// POC: findById で全ユーザーを取得
userRepository.findById('1 OR 1=1').then(console.log);

// POC: 認証バイパス
userRepository.authenticate("' OR '1'='1' --","irrelevant").then(user => console.log(user));

// POC: 任意テーブル削除
userRepository.executeQuery("DROP TABLE users; --");
```

## 関連コードコンテキスト

### 関数名: findById
- 理由: ID パラメータを直接埋め込んでおり、数値以外の文字列や論理式を注入可能
- パス: ./infrastructure/database/UserRepository.js
```rust
const query = `SELECT * FROM users WHERE id = ${id}`;
```

### 関数名: findByUsername
- 理由: ユーザー名をサニタイズせずにクエリ文字列に連結しており、文字列閉じやコメントアウトを使った注入が可能
- パス: ./infrastructure/database/UserRepository.js
```rust
const query = `SELECT * FROM users WHERE username = '${username}'`;
```

### 関数名: findAll
- 理由: search フィルタをそのまま LIKE 句に埋め込んでおり、任意の SQL 文を組み込める
- パス: ./infrastructure/database/UserRepository.js
```rust
if (filters.search) { query += ` AND (username LIKE '%${filters.search}%' OR email LIKE '%${filters.search}%')`; }
```

### 関数名: create
- 理由: 挿入値を文字列連結で組み立てており、複数行注入やサブクエリ注入が可能
- パス: ./infrastructure/database/UserRepository.js
```rust
const query = `INSERT INTO users (username, password, email, role) VALUES ('${username}', '${password}', '${email}', '${role || 'user'}')`;
```

### 関数名: authenticate
- 理由: 認証クエリに直接パスワードを埋め込んでおり、常に真になる条件の注入で認証をバイパス可能
- パス: ./infrastructure/database/UserRepository.js
```rust
const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
```

### 関数名: executeQuery
- 理由: 任意のクエリを文字列で受け取り実行しており、完全な任意 SQL 実行を許可している
- パス: ./infrastructure/database/UserRepository.js
```rust
this.db.all(query, params, (err, rows) => { ... });
```

## 解析ノート

複数のメソッドで SQL インジェクション脆弱性を検出。executeQuery により完全な任意クエリ実行も可能。

