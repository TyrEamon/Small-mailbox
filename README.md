# cf-mail-compat

一个部署在 Cloudflare Workers 上的极简临时邮箱 API，严格兼容 `nvidia-register` 的 `EMAIL_API_SPEC.md`。

## 支持的接口

| 功能 | 方法 | 路径 | 认证 |
| --- | --- | --- | --- |
| 创建地址 | `POST` | `/admin/new_address` | `x-admin-auth: EMAIL_AUTH` |
| 邮件列表 | `GET` | `/api/mails?limit=5&offset=0` | `Authorization: Bearer {jwt}` |
| 邮件详情 | `GET` | `/api/mail/{id}` | `Authorization: Bearer {jwt}` |

## 工作方式

- Cloudflare Email Routing 使用 catch-all：`*@EMAIL_DOMAIN -> Worker`
- Worker 的 `email()` handler 接收任意前缀邮箱
- D1 保存邮件索引
- R2 保存完整 raw MIME；如果你手动绑定 `MAIL_KV` 而不是 `MAIL_RAW`，也能作为小邮件 fallback 使用
- JWT 绑定单个邮箱地址，不能跨邮箱读取

推荐 raw 邮件用 R2：邮件原文可能很大，KV 有单 value 限制；R2 更适合对象数据。

## 推荐部署：GitHub 连接 Cloudflare，资源手动创建

这个项目按你的偏好设计成：

- 代码从 GitHub 自动部署
- D1 你手动创建
- R2 或 KV 你手动创建
- 变量和 secrets 你在 Cloudflare 后台手动填
- 绑定在 Cloudflare 后台手动加，不需要先写进 `wrangler.jsonc`
- Worker 第一次请求或第一次收信时会自动初始化 D1 表

步骤见 `GitHub自动部署步骤.md`。

## 本地开发

```bash
cd D:\Desktop\cf-mail-compat
npm install
copy .dev.vars.example .dev.vars
npm run dev
```

## 手动 Wrangler 部署

```bash
npm install
npx wrangler secret put EMAIL_AUTH
npx wrangler secret put JWT_SECRET
npm run deploy
```

部署后在 Cloudflare Dashboard 里配置 Email Routing：

```text
*@tyrlink.dpdns.org -> cf-mail-compat Worker
```

如果你要支持多个域名，在 Worker 的 runtime variables 里添加：

```text
EMAIL_DOMAINS = "tyrlink.dpdns.org,tyr01.netlib.re"
```

并分别给这些域名配置 Email Routing catch-all。

## 接口测试

创建地址：

```bash
curl -X POST "%EMAIL_API%/admin/new_address" ^
  -H "x-admin-auth: %EMAIL_AUTH%" ^
  -H "content-type: application/json" ^
  -d "{\"name\":\"001\",\"domain\":\"tyrlink.dpdns.org\",\"enablePrefix\":false}"
```

返回：

```json
{
  "address": "001@tyrlink.dpdns.org",
  "jwt": "..."
}
```

查询列表：

```bash
curl "%EMAIL_API%/api/mails?limit=5&offset=0" ^
  -H "Authorization: Bearer %JWT%"
```

查询详情：

```bash
curl "%EMAIL_API%/api/mail/%MAIL_ID%" ^
  -H "Authorization: Bearer %JWT%"
```

## nvidia-register `.env`

```ini
EMAIL_API=https://你的-worker-域名
EMAIL_AUTH=和 Worker 里的 EMAIL_AUTH 一致
EMAIL_DOMAIN=tyrlink.dpdns.org
NV_PASSWORD=你的 NVIDIA 密码
```

## 注意

- `/api/mail/{id}` 返回的 `raw` 是完整原始邮件文本，脚本可直接用正则提取 `123-456`。
- `RETENTION_HOURS` 默认是 `1`，计划任务每 30 分钟清理一次旧邮件。
- `MAX_RAW_BYTES` 默认是 `2097152`，也就是 2MB，超大邮件会拒收。
