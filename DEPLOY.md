# 工廠管理系統部署說明

## Cloudflare 架構

GitHub 保留作為程式碼來源，Cloudflare Pages 負責前端與 Pages Functions，D1 負責保存工作看板資料。`server.js` 仍保留給本機測試；正式環境使用 `functions/_middleware.js`。

## 登入功能

- 共用一組帳號密碼，可同時在多台設備登入。
- 每台設備會取得獨立的 HttpOnly、SameSite Cookie，有效 30 天。
- 登入後 `/api/state` 才能讀取或寫入資料。
- 修改 `FACTORY_SESSION_SECRET` 後，原登入 Cookie 會失效。

## Cloudflare 設定

1. 建立 Pages 專案，連接 GitHub repository，網站根目錄指向本資料夾。
2. 建立 D1 資料庫，執行 `migrations/0001_init.sql`。
3. 在 Pages Settings → Functions → D1 database bindings 將 `DB` 綁定到資料庫。
4. 建立加密環境變數／Secrets：

```text
FACTORY_USERNAME=公司登入帳號
FACTORY_PASSWORD_HASH=由 scripts/hash-password.mjs 產生的值
FACTORY_SESSION_SECRET=至少 32 位的隨機字串
```

5. 部署後使用 `scripts/seed-state.mjs` 將本機 `data/state.json` 匯入 D1。
6. 在 Cloudflare Pages 加入公司網域並啟用 HTTPS。

不要把 `.env`、正式密碼或 `data/state.json` 上傳到 GitHub。GitHub Pages 本身只能提供靜態檔案，不能承擔登入 API 或 D1 存取。
