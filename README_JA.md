# edge-rate-limiter (日本語ドキュメント)

Edge、Cloudflare Workers、Node.js 向けの、ゼロ依存・暗号学的スライディングウィンドウ＆トークンバケット型レートリミッター。外部依存ゼロで動作します。

---

## 特長

1. **外部依存ゼロ**: 追加パッケージ不要の完全自前実装。
2. **Zero-PII IP 匿名化**: IPアドレスを生で保持せず、ソルト付きハッシュでキー化。
3. **IETF RateLimit 標準ヘッダー対応**: `RateLimit-Limit`, `RateLimit-Remaining`, `RateLimit-Reset`, `Retry-After` を自動出力。
4. **プラガブルなストア設計**: インメモリストアおよび分散KV/キャッシュ向けインターフェースを提供。
