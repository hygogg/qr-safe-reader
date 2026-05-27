# QR Guard

読み取ったQRコードのURLをそのまま開かず、URL正規化、危険パターン検査、DNS確認、リダイレクト確認を行ってから開けるQRコードリーダーです。

## できること

- カメラでQRコードを読み取り
- QR画像ファイルから読み取り
- 手入力URLの検査
- `http(s)` 以外、ローカル/内部ネットワーク宛先、実行ファイル、認証情報入りURLなどを警告またはブロック
- DNS解決先とリダイレクト先を確認
- 判定後にだけ外部URLを開く

## 起動

```bash
cd qr-safe-reader
node server/index.mjs
```

ブラウザで開きます。

```text
http://localhost:8080
```

## Docker

```bash
docker compose up --build
```

## Vercel

GitHub リポジトリを Vercel にインポートすると、そのままデプロイできます。

- Framework Preset: `Other`
- Build Command: 空欄
- Output Directory: 空欄
- Install Command: 空欄でも可

静的UIは `public/` から配信され、URL検査APIは `api/analyze.mjs` と `api/healthz.mjs` の Serverless Function として動きます。

## 判定について

このアプリはURLの構造、DNS、リダイレクト、HTTPメタデータを検査します。外部の脅威インテリジェンスAPIには依存していないため、未知のフィッシングサイトや侵害直後の正規サイトを完全に保証するものではありません。本番運用では Google Safe Browsing、VirusTotal、社内プロキシログなどのレピュテーション情報を追加するのが次の拡張候補です。
