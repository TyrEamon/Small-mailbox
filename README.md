# Small Mailbox

Cloudflare Workers 上的轻量域名邮箱面板，保留 `nvidia-register` 需要的 3 个兼容接口，同时新增网页前端、账号密码、兑换码和批量创建邮箱。

## 已支持

- 网页面板：访问 Worker 根路径 `/` 即可登录、注册、兑换次数、创建邮箱、查看邮件。
- 无限前缀：只要域名配置了 Email Routing catch-all，`001@域名`、`002@域名`、`jsbxbx@域名` 都能收。
- 次数售卖：管理员生成 50/100 次兑换码，用户注册后兑换；每创建 1 个邮箱消耗 1 次。
- 批量创建：随机批量生成，或用 `nv + 001/002/003` 这类编号批量创建。
- 邮件存储：D1 保存索引；R2 保存完整 raw 邮件，KV 可作为 fallback。

## 兼容接口

| 功能 | 方法 | 路径 | 认证 |
| --- | --- | --- | --- |
| 创建地址 | `POST` | `/admin/new_address` | `x-admin-auth: EMAIL_AUTH` |
| 邮件列表 | `GET` | `/api/mails?limit=5&offset=0` | `Authorization: Bearer {jwt}` |
| 邮件详情 | `GET` | `/api/mail/{id}` | `Authorization: Bearer {jwt}` |

这些接口不要删，`nvidia-register` 可以继续直接对接。

## 网页接口

| 功能 | 方法 | 路径 |
| --- | --- | --- |
| 注册 | `POST` | `/app/api/register` |
| 登录 | `POST` | `/app/api/login` |
| 当前用户 | `GET` | `/app/api/me` |
| 兑换次数 | `POST` | `/app/api/redeem` |
| 地址列表 | `GET` | `/app/api/addresses` |
| 创建 1 个地址 | `POST` | `/app/api/addresses` |
| 批量创建地址 | `POST` | `/app/api/addresses/batch` |
| 用户邮件列表 | `GET` | `/app/api/mails?address=xxx@domain` |
| 用户邮件详情 | `GET` | `/app/api/mail/{id}` |
| 管理员生成兑换码 | `POST` | `/admin/redeem_codes` |

## Cloudflare 手动配置

GitHub 连接部署时，本仓库不在 `wrangler.jsonc` 写死资源 ID。你在 Cloudflare 网页后台手动创建并绑定：

| 类型 | 绑定名 | 用途 |
| --- | --- | --- |
| D1 | `MAIL_DB` | 用户、额度、地址、邮件索引 |
| R2 | `MAIL_RAW` | 推荐，保存 raw 邮件 |
| KV | `MAIL_KV` | 可选 fallback；没有 R2 时才用 |

至少需要 `MAIL_DB`，并且 `MAIL_RAW` / `MAIL_KV` 二选一。推荐 D1 + R2。

## 环境变量

| 变量名 | 示例值 | 说明 |
| --- | --- | --- |
| `EMAIL_AUTH` | `change-me-admin-secret` | 管理员密钥，用来创建地址和生成兑换码 |
| `JWT_SECRET` | `change-me-jwt-secret` | JWT 签名密钥；不填时会 fallback 到 `EMAIL_AUTH` |
| `EMAIL_DOMAIN` | `tyrlink.dpdns.org` | 默认收信域名 |
| `EMAIL_DOMAINS` | `tyrlink.dpdns.org,example.com` | 多域名可选，逗号分隔 |
| `ALLOW_REGISTRATION` | `true` | 是否允许公开注册；想只给邀请用户就设 `false` |
| `MAX_BATCH_CREATE` | `100` | 单次批量创建上限 |
| `RETENTION_HOURS` | `0` | 邮件保留小时数；`0` 表示不自动清理 |
| `MAX_RAW_BYTES` | `2097152` | 单封 raw 邮件最大字节数，默认 2MB |

## D1 建表

Worker 首次 API 请求会自动建表和迁移 `addresses.user_id`。如果你想手动建，也可以在 D1 控制台运行 `schema.sql`。

## 给别人使用的流程

1. 你在网页后台绑定 D1、R2、变量并部署。
2. 你打开 Worker 根路径 `/`，在“管理员发码”里输入 `EMAIL_AUTH`。
3. 生成一个 50 次或 100 次兑换码。
4. 买家自己注册账号、兑换次数。
5. 买家批量创建邮箱，或一个一个创建 `001`、`002`、`jsbxbx` 等自定义前缀。
6. 买家在网页里查看这些邮箱收到的邮件和验证码。

## 本地开发

```bash
cd D:\Desktop\cf-mail-compat
npm install
copy .dev.vars.example .dev.vars
npm run dev
```

## 部署命令

Cloudflare 连接 GitHub 时：

- 构建命令：留空或 `npm install`
- 部署命令：留空

如果用 Wrangler 手动部署：

```bash
npm install
npm run deploy
```

## nvidia-register `.env`

```ini
EMAIL_API=https://你的-worker-域名
EMAIL_AUTH=和 Worker 里的 EMAIL_AUTH 一致
EMAIL_DOMAIN=tyrlink.dpdns.org
NV_PASSWORD=你的 NVIDIA 密码
```

`/api/mail/{id}` 返回的 `raw` 是完整原始邮件文本，脚本可以继续用正则提取 `123-456` 这类验证码。
