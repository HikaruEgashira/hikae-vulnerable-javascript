# Vulnerable JavaScript Application - Security Analysis

このリポジトリはセキュリティテスト・学習用に設計された**意図的に脆弱なNode.js Webアプリケーション**です。

> ⚠️ **警告**: 本番環境では絶対に使用しないでください。隔離されたテスト環境でのみ使用してください。

## 脆弱性一覧

### 1. SQLインジェクション (CWE-89)

**場所:**
- `app.js:539` - ログインクエリ
- `app.js:735` - ユーザー検索
- `routes/auth.js:21` - 認証クエリ
- `api.js:47`, `api.js:100`, `api.js:119-130` - 各種APIエンドポイント

**問題:**
```javascript
const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
```

**推奨される修正:**
```javascript
const query = `SELECT * FROM users WHERE username = ? AND password = ?`;
db.get(query, [username, password], (err, user) => { ... });
```

---

### 2. コマンドインジェクション (CWE-78)

**場所:**
- `app.js:797-798` - `/cmdi` エンドポイント
- `api.js:323-324` - `/api/system/execute`
- `routes/files.js:200-202` - ファイル圧縮
- `routes/advanced.js:206`, `212-213` - ファイル操作

**問題:**
```javascript
const output = execSync(fullCommand, { encoding: 'utf8' });
```

**推奨される修正:**
```javascript
const { spawn } = require('child_process');
const child = spawn(command, args, { shell: false });
```

---

### 3. クロスサイトスクリプティング - XSS (CWE-79)

**場所:**
- `app.js:759-778` - `/xss` エンドポイント
- `app.js:742-749` - 検索結果の表示
- `routes/bypass.js:132-147` - フィルタテスト

**問題:**
```javascript
res.send(`<p>Hello, ${name}!</p>`);
```

**推奨される修正:**
```javascript
const escapeHtml = require('escape-html');
res.send(`<p>Hello, ${escapeHtml(name)}!</p>`);
```

---

### 4. パストラバーサル / LFI (CWE-22)

**場所:**
- `api.js:344` - `/api/file/read`
- `routes/files.js:82` - ファイル読み取り
- `routes/files.js:103` - ディレクトリ一覧

**問題:**
```javascript
const content = fs.readFileSync(filePath, 'utf8');
```

**推奨される修正:**
```javascript
const safePath = path.resolve(baseDir, path.basename(filePath));
if (!safePath.startsWith(baseDir)) {
    throw new Error('Invalid path');
}
```

---

### 5. SSRF - Server-Side Request Forgery (CWE-918)

**場所:**
- `api.js:194-209` - `/api/ssrf/fetch`
- `api.js:211-229` - `/api/scraper/url`

**問題:**
```javascript
const response = await axios.get(url, { timeout });
```

**推奨される修正:**
```javascript
const allowedHosts = ['api.example.com'];
const parsedUrl = new URL(url);
if (!allowedHosts.includes(parsedUrl.hostname)) {
    throw new Error('Host not allowed');
}
// プライベートIPアドレスの検証も追加
```

---

### 6. 認証・認可の脆弱性 (CWE-287, CWE-639)

**場所:**
- `middleware/auth.js:30-33` - デバッグモードバイパス
- `middleware/auth.js:45-48` - ハードコードされたバイパストークン
- `middleware/auth.js:56` - `none`アルゴリズムの許可
- `middleware/auth.js:129-141` - ヘッダーによるロールオーバーライド

**問題:**
```javascript
if (debugMode === 'true') {
    req.user = { id: 1, username: 'debug_user', role: 'admin' };
    return next();
}
jwt.verify(token, JWT_SECRET, { algorithms: ['HS256', 'none'] });
```

**推奨される修正:**
```javascript
// デバッグモードを削除
// noneアルゴリズムを禁止
jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });
```

---

### 7. 暗号化の脆弱性 (CWE-327, CWE-328)

**場所:**
- `services/crypto.js:37` - MD5パスワードハッシュ
- `services/crypto.js:48-51` - AES-ECBモード
- `services/crypto.js:94` - SHA1 HMAC
- `services/crypto.js:258` - 弱いJWTシークレット
- `services/crypto.js:169-185` - Math.randomによるトークン生成

**問題:**
```javascript
const hash = crypto.createHash('md5').update(password + salt).digest('hex');
const cipher = crypto.createCipher('aes-256-ecb', this.encryptionKey);
```

**推奨される修正:**
```javascript
const bcrypt = require('bcrypt');
const hash = await bcrypt.hash(password, 12);
// AES-GCMまたはAES-CBC + HMACを使用
const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
```

---

### 8. ハードコードされた秘密情報 (CWE-798)

**場所:**
- `app.js:42-47` - JWT_SECRET, API_KEYS
- `config/constants.js:9-11` - JWT_CONFIG
- `config/constants.js:15-20` - API_TOKENS
- `config/constants.js:38-43` - MAINTENANCE_TOKENS
- `middleware/auth.js:12-13` - JWT_SECRET, バイパストークン

**問題:**
```javascript
const JWT_SECRET = 'super_secret_js_key_123';
const API_KEYS = { 'sk-js-1234567890abcdef': 'admin' };
```

**推奨される修正:**
```javascript
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET || JWT_SECRET.length < 32) {
    throw new Error('Invalid JWT_SECRET configuration');
}
```

---

### 9. プロトタイプ汚染 (CWE-1321)

**場所:**
- `api.js:280-291` - lodash.merge
- `api.js:293-315` - カスタムdeepMerge

**問題:**
```javascript
const mergedConfig = _.merge(defaultConfig, config);
```

**推奨される修正:**
```javascript
// __proto__, constructor, prototypeキーをフィルタリング
function safeMerge(target, source) {
    const forbidden = ['__proto__', 'constructor', 'prototype'];
    for (const key in source) {
        if (forbidden.includes(key)) continue;
        // ...
    }
}
```

---

### 10. テンプレートインジェクション - SSTI (CWE-94)

**場所:**
- `api.js:252-264` - Handlebarsテンプレート
- `api.js:266-277` - EJSテンプレート
- `routes/advanced.js:327-329` - eval in query resolution

**問題:**
```javascript
const compiledTemplate = handlebars.compile(template);
ejs.render(template, context || {});
```

**推奨される修正:**
```javascript
// ユーザー入力をテンプレートとして使用しない
// プリコンパイルされたテンプレートのみ使用
const template = templates.get(templateName);
template(sanitizedContext);
```

---

### 11. 安全でないデシリアライゼーション (CWE-502)

**場所:**
- `api.js:411-421` - serialize with unsafe option
- `api.js:423-433` - eval for deserialization

**問題:**
```javascript
const serialized = serialize(data, { unsafe: true });
const deserialized = eval(`(${serialized})`);
```

**推奨される修正:**
```javascript
// evalを使用しない
const deserialized = JSON.parse(serialized);
```

---

### 12. 情報漏洩 (CWE-200)

**場所:**
- `app.js:949` - 環境変数の露出
- `app.js:552` - エラーメッセージにクエリを含む
- `api.js:55`, `137` - クエリ文字列の露出
- `middleware/auth.js:79` - JWTシークレットのヒント露出

**問題:**
```javascript
environment: process.env
return res.status(500).send(`Database error: ${err.message}<br>Query: ${query}`);
```

**推奨される修正:**
```javascript
// 本番環境では詳細なエラー情報を返さない
res.status(500).json({ error: 'Internal server error' });
```

---

### 13. セッション管理の脆弱性 (CWE-384)

**場所:**
- `app.js:66-75` - 安全でないセッション設定
- `config/constants.js:23-28` - SESSION_OPTIONS

**問題:**
```javascript
cookie: {
    secure: false,    // HTTPSなしで送信
    httpOnly: false,  // JavaScriptからアクセス可能
}
```

**推奨される修正:**
```javascript
cookie: {
    secure: true,
    httpOnly: true,
    sameSite: 'strict'
}
```

---

### 14. タイミング攻撃 (CWE-208)

**場所:**
- `services/crypto.js:112-126` - HMAC検証
- `services/crypto.js:289-309` - secureCompare
- `routes/advanced.js:358-383` - 分散システム秘密検証

**問題:**
```javascript
for (let i = 0; i < signature.length; i++) {
    if (signature[i] !== expected[i]) break;
    await new Promise(resolve => setTimeout(resolve, 10));
}
```

**推奨される修正:**
```javascript
const crypto = require('crypto');
const isValid = crypto.timingSafeEqual(
    Buffer.from(signature),
    Buffer.from(expected)
);
```

---

### 15. IDOR - Insecure Direct Object Reference (CWE-639)

**場所:**
- `api.js:96-113` - `/api/user/:id`
- `api.js:146-163` - `/api/documents/:id`
- `api.js:449-461` - `/api/logs/:user_id`
- `app.js:896-927` - `/logs`

**問題:**
```javascript
router.get('/user/:id', (req, res) => {
    const userId = req.params.id;
    const query = `SELECT * FROM users WHERE id = ${userId}`;
    // 認可チェックなし
});
```

**推奨される修正:**
```javascript
router.get('/user/:id', authenticate, (req, res) => {
    const userId = req.params.id;
    if (req.user.id !== parseInt(userId) && req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Access denied' });
    }
    // ...
});
```

---

### 16. ファイルアップロードの脆弱性 (CWE-434)

**場所:**
- `app.js:78-85` - ファイルフィルタなし
- `routes/files.js:25-45` - アップロード処理
- `middleware/validation.js:237-279` - バイパス可能な検証

**問題:**
```javascript
const upload = multer({
    dest: '/tmp/uploads/',
    fileFilter: (req, file, cb) => cb(null, true)  // すべて許可
});
```

**推奨される修正:**
```javascript
const upload = multer({
    dest: '/tmp/uploads/',
    fileFilter: (req, file, cb) => {
        const allowedTypes = ['image/jpeg', 'image/png'];
        if (!allowedTypes.includes(file.mimetype)) {
            return cb(new Error('Invalid file type'), false);
        }
        cb(null, true);
    },
    limits: { fileSize: 5 * 1024 * 1024 }  // 5MB
});
```

---

### 17. Zip Slip脆弱性 (CWE-22)

**場所:**
- `api.js:387-408` - `/api/archive/extract`
- `routes/files.js:160-185` - アーカイブ展開

**問題:**
```javascript
await extract(req.file.path, { dir: extractDir });
```

**推奨される修正:**
```javascript
// 展開前にパスを検証
const AdmZip = require('adm-zip');
const zip = new AdmZip(archivePath);
zip.getEntries().forEach(entry => {
    const targetPath = path.join(extractDir, entry.entryName);
    if (!targetPath.startsWith(extractDir)) {
        throw new Error('Path traversal detected');
    }
});
```

---

### 18. レート制限のバイパス (CWE-770)

**場所:**
- `middleware/auth.js:85-122` - レート制限ミドルウェア
- `config/constants.js:61-65` - THROTTLE_CONFIG

**問題:**
```javascript
if (req.headers['x-bypass-rate-limit'] === 'true' ||
    userAgent.includes('bot')) {
    return next();
}
```

**推奨される修正:**
```javascript
// バイパスヘッダーを削除
// IPベースの制限を適切に実装
const rateLimit = require('express-rate-limit');
app.use(rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    standardHeaders: true,
    legacyHeaders: false
}));
```

---

### 19. CSRF保護のバイパス (CWE-352)

**場所:**
- `middleware/auth.js:197-219` - CSRF保護

**問題:**
```javascript
if (req.headers['x-requested-with'] === 'XMLHttpRequest' ||
    origin?.includes('localhost')) {
    return next();
}
```

**推奨される修正:**
```javascript
const csrf = require('csurf');
app.use(csrf({ cookie: true }));
```

---

### 20. VMサンドボックスエスケープ (CWE-94)

**場所:**
- `routes/advanced.js:231-274` - `/advanced/vm/execute`

**問題:**
```javascript
const vmContext = {
    global: global,  // グローバルオブジェクトへのアクセス
    // ...
};
```

**推奨される修正:**
```javascript
// 信頼できないコードを実行しない
// vm2や隔離されたコンテナを使用
```

---

## セキュリティ設定チェックリスト

- [ ] 環境変数で秘密情報を管理
- [ ] HTTPSを強制
- [ ] セキュリティヘッダーを設定 (helmet)
- [ ] 適切なCORS設定
- [ ] 入力検証とサニタイゼーション
- [ ] パラメータ化クエリの使用
- [ ] 安全な暗号化アルゴリズムの使用
- [ ] 適切なエラーハンドリング
- [ ] ログから機密情報を除外
- [ ] 依存関係の脆弱性スキャン

## 開発時の注意

```bash
# 依存関係の脆弱性チェック
npm audit

# 起動（テスト環境のみ）
node app.js        # レガシー版
node app-clean.js  # クリーンアーキテクチャ版
```

## 参考資料

- [OWASP Top 10](https://owasp.org/Top10/)
- [CWE/SANS Top 25](https://cwe.mitre.org/top25/)
- [Node.js Security Best Practices](https://nodejs.org/en/docs/guides/security/)
