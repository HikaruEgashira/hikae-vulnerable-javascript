# 解析レポート

![高信頼度](https://img.shields.io/badge/信頼度-高-red) **信頼度スコア: 90**

## 脆弱性タイプ

- `SQLI`

## 解析結果

以下のポイントで深刻なSQLインジェクション脆弱性が認められます。ユーザ入力（username, password, email, newPassword, role）をサニタイズせずにSQLクエリ文字列に直接埋め込んでいるため、攻撃者は任意のSQLを実行できます。

## PoC（概念実証コード）

```text
POST /auth/login
Content-Type: application/json

{
  "username": "' OR '1'='1",
  "password": "any"
}
```

## 関連コードコンテキスト

### 関数名: Loginエンドポイント
- 理由: 認証時にusernameとpasswordを直接埋め込んでおり、SQLインジェクション可能
- パス: ./routes/auth.js
```rust
const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
```

### 関数名: reset-passwordエンドポイント
- 理由: メールアドレスを直接WHERE句に埋め込み、SQLインジェクション可能
- パス: ./routes/auth.js
```rust
const query = `UPDATE users SET reset_token = '${resetToken}' WHERE email = '${email}'`;
```

### 関数名: change-passwordエンドポイント
- 理由: パスワード変更時にnewPassword/usernameが未検証のまま埋め込まれ、SQLインジェクション可能
- パス: ./routes/auth.js
```rust
const query = `UPDATE users SET password = '${newPassword}' WHERE username = '${username}'`;
```

### 関数名: registerエンドポイント
- 理由: ユーザ登録で任意のroleやemailを直接埋め込み、SQLインジェクション可能
- パス: ./routes/auth.js
```rust
const query = `INSERT INTO users (username, password, email, role) VALUES ('${username}', '${password}', '${email}', '${userRole}')`;
```

## 解析ノート

ユーザ入力→直接クエリ埋め込み→SQLインジェクション脆弱性特定

