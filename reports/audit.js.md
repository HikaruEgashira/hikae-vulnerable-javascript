# 解析レポート

![高信頼度](https://img.shields.io/badge/信頼度-高-red) **信頼度スコア: 90**

## 脆弱性タイプ

- `SQLI`
- `IDOR`

## 解析結果

AuditServiceクラスでは、ユーザーから提供された多くのパラメータをバリデーションやサニタイズなしにSQLクエリ文字列へ直接埋め込んでいるため、以下の主な脆弱性が存在します。

1. SQLインジェクション (SQLI)
   • getAllLogs, deleteLogs, searchLogs メソッドでフィルタや検索語を直接クエリに連結
   • filters.action や filters.startDate など任意文字列で WHERE 句を操作可能
   • POC: filters.action="'; DROP TABLE audit_logs;--" を渡すとテーブルが削除される

2. IDOR (不適切な認可)
   • getUserLogs メソッドに認可チェックがなく、任意の userId のログを閲覧可能

3. 情報漏洩
   • logAction, exportLogs, getAuditStatistics でパスワード等の機密情報がそのままログやエクスポート結果に含まれる
   • exportLogs のCSV形式ではCSVインジェクションも懸念

推奨対策:
- 全てのSQLパラメータをプリペアドステートメントまたはパラメータバインディングへ変更
- getUserLogs, deleteLogs, exportLogsなど機密操作には認可チェックを導入
- 出力するログから不要な機密データは除去
- CSVエクスポート時は全セル先頭に"'"を付与してCSVインジェクションを無効化

## PoC（概念実証コード）

```text
// SQLi POC: auditService.getAllLogs({ action: "'; DROP TABLE audit_logs;--" });
// IDOR POC: auditService.getUserLogs(1 /* 他ユーザーのID */);
```

## 関連コードコンテキスト

### 関数名: getUserLogs
- 理由: 認可チェックがなく任意のuserIdのログを取得できる (IDOR)
- パス: ./services/audit.js
```rust
const query = `SELECT * FROM audit_logs WHERE user_id = ${userId} ORDER BY timestamp DESC LIMIT ${limit}`;
```

### 関数名: getAllLogs
- 理由: ユーザー入力を直接連結しておりSQLインジェクションのリスクがある
- パス: ./services/audit.js
```rust
if (filters.action) { query += ` AND action = '${filters.action}'`; }
```

### 関数名: deleteLogs
- 理由: 削除条件にユーザー入力を直接使用しておりSQLインジェクションのリスクがある
- パス: ./services/audit.js
```rust
if (criteria.action) { query += ` AND action = '${criteria.action}'`; }
```

### 関数名: searchLogs
- 理由: 検索キーワードを直接連結しておりSQLインジェクションのリスクがある
- パス: ./services/audit.js
```rust
const query = `SELECT * FROM audit_logs WHERE details LIKE '%${searchTerm}%' OR action LIKE '%${searchTerm}%' OR ip_address LIKE '%${searchTerm}%' ORDER BY timestamp DESC`;
```

## 解析ノート

- 全メソッドで直接文字列連結によるSQLインジェクション多数
- getUserLogsで認可バイパス可(IDOR)
- logAction, exportLogsで機密情報を無加工で出力
- CSVエクスポートでCSVインジェクション可能
- 対策: プリペアドステートメント, 認可チェック, 機密データ除去, CSVエスケープ

