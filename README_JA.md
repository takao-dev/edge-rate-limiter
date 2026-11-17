# edge-rate-limiter (日本語ドキュメント)

Edge、Cloudflare Workers、Node.js 向けの、ゼロ依存・固定ウィンドウ型レートリミッター。外部依存ゼロで動作します。

## ストレージキーの互換性と移行

ソルト付きクライアントキーの導出を、バージョン付きドメインを使うHMAC-SHA-256に変更しました。既存バケットは異なるストレージキーを使うため読み込まれず、アップグレード後は対象クライアントのクォータが満額から始まります。このクォータリセットを考慮して切り替え、インスタンス間・デプロイ間で同じ秘密ソルトを維持してください。

---

## 特長

1. **外部依存ゼロ**: 追加パッケージ不要の完全自前実装。
2. **Zero-PII IP 匿名化**: IPアドレスを生で保持せず、ソルト付きHMACでキー化。
3. **IETF RateLimit 標準ヘッダー対応**: `RateLimit-Limit`, `RateLimit-Remaining`, `RateLimit-Reset`, `Retry-After` を自動出力。
4. **プラガブルなストア設計**: インメモリストアおよび分散KV/キャッシュ向けインターフェースを提供。

---

## 関連エッジセキュリティパッケージ群

- [wasm-crypto-hash](https://github.com/takao-dev/wasm-crypto-hash): 超高速 WebAssembly & WebCrypto 暗号化スイート (SHA-2/3, BLAKE3, PQC, Argon2, TOTP, BIP-39)
- [edge-secure-token](https://github.com/takao-dev/edge-secure-token): タイミング攻撃耐性を持つ WebCrypto ベースの JWT & クレーム暗号化スイート
- [edge-session-crypto](https://github.com/takao-dev/edge-session-crypto): AES-GCM と鍵ローテーションを備えたステートレス暗号化クッキーセッション管理
- [zero-pii-redactor](https://github.com/takao-dev/zero-pii-redactor): ログ・AIプロンプト向けの超高速・ReDoSフリー PII マスキング＆匿名化ツール
- [webcrypto-secure-storage](https://github.com/takao-dev/webcrypto-secure-storage): AES-GCM & HMAC による改ざん検知機能付きセキュアKVストレージ
- [edge-audit-crypto](https://github.com/takao-dev/edge-audit-crypto): 暗号論的ハッシュチェーンによる改ざん耐性監査ログ記録
