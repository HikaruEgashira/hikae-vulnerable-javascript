# 解析レポート

![中高信頼度](https://img.shields.io/badge/信頼度-中高-orange) **信頼度スコア: 80**

## 脆弱性タイプ

- `SQLI`
- `IDOR`

## 解析結果

本コードではユーザー入力をそのままSQLクエリに埋め込んでおり、SQLインジェクション(SQLI)と認可チェック漏れ(IDOR)が顕著です。

1. SQLインジェクション
   - searchUsers: username、email、role、orderBy、limit、offsetを文字列連結でそのままクエリに組み込んでいるため任意のSQLが実行可能です。
   - authenticateUser/createUser/updateUser: ユーザー名・パスワード・メール・ロールを直接埋め込んでおり、認証バイパスやテーブル操作が可能です。

2. IDOR (認可チェック漏れ)
   - deleteUser/getUserProfile: userIdだけで操作を許可しており、他ユーザーのプロファイル参照や削除が行えます。

影響: 全ユーザーの情報漏洩、認証バイパス、管理者権限取得、データ操作・破壊など。

## PoC（概念実証コード）

```text
1) SQLインジェクション(searchUsers):
   GET /api/users?username=' OR '1'='1
   -> 全ユーザーが返却される

2) 認証バイパス(authenticateUser):
   username=admin'--&password=anything
   -> 管理者アカウントでログイン可能

3) IDOR(deleteUser):
   DELETE /api/users/2
   -> 他ユーザーIDを指定してアカウント削除

4) IDOR(getUserProfile):
   GET /api/user/profile?userId=5
   -> 他ユーザーのプロフィール取得
```

## 関連コードコンテキスト

### 関数名: searchUsers
- 理由: 動的にパラメータを連結しておりSQLインジェクションの入り口となる
- パス: ./services/user.js
```rust
let query = `SELECT id, username, email, role, created_at FROM users WHERE 1=1`;
```

### 関数名: searchUsers
- 理由: ユーザー入力をエスケープせずに連結している
- パス: ./services/user.js
```rust
query += ` AND username LIKE '%${username}%'`;
```

### 関数名: authenticateUser
- 理由: 認証時にSQLインジェクションが可能
- パス: ./services/user.js
```rust
const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
```

### 関数名: updateUser
- 理由: 任意のカラム更新とロール変更およびSQLインジェクションの恐れ
- パス: ./services/user.js
```rust
const query = `UPDATE users SET ${setParts.join(', ')} WHERE id = ${userId}`;
```

### 関数名: deleteUser
- 理由: 認可チェックがなく他ユーザーを削除可能
- パス: ./services/user.js
```rust
const query = `DELETE FROM users WHERE id = ${userId}`;
```

### 関数名: getUserProfile
- 理由: 認可チェックがなくIDORによる情報漏洩
- パス: ./services/user.js
```rust
const query = `SELECT u.*, up.profile_data, up.permissions FROM users u LEFT JOIN user_profiles up ON u.id = up.user_id WHERE u.id = ${userId}`;
```

## 解析ノート

- 複数メソッドで文字列連結によるSQL発行を確認
- ロールエスカレーションや認可チェック漏れがある
- 検証不足・エスケープ不足が根本原因
- 対策: プレースホルダ利用、入力検証、認可ミドルウェア導入

