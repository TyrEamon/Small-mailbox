# Small Mailbox

Cloudflare Workers 上的轻量域名邮箱面板，保留 `nvidia-register` 需要的 3 个兼容接口，同时新增网页前端、账号密码、激活码和批量创建邮箱。

## 已支持

- 网页面板：访问 Worker 根路径 `/` 即可统一登录；管理员账号进入后台，用户账号进入邮箱面板。
- 无限前缀：只要域名配置了 Email Routing catch-all，`001@域名`、`002@域名`、`jsbxbx@域名` 都能收。
- 次数售卖：管理员生成 50/100 次激活码，用户注册时填激活码，账号创建后直接得到次数；每创建 1 个邮箱消耗 1 次。
- 批量创建：随机批量生成，或用 `nv + 001/002/003` 这类编号批量创建。
- 用户 API Key：买家可以生成自己的 `EMAIL_AUTH`，直接给脚本调用，不需要你的管理员密钥。
- 邮件存储：D1 保存索引；R2 保存完整 raw 邮件，KV 可作为 fallback。

## 兼容接口

| 功能 | 方法 | 路径 | 认证 |
| --- | --- | --- | --- |
| 创建地址 | `POST` | `/admin/new_address` | `x-admin-auth: EMAIL_AUTH` |
| 邮件列表 | `GET` | `/api/mails?limit=5&offset=0` | `Authorization: Bearer {jwt}` |
| 邮件详情 | `GET` | `/api/mail/{id}` | `Authorization: Bearer {jwt}` |

这些接口不要删，`nvidia-register` 可以继续直接对接。

`POST /admin/new_address` 现在支持两类 `EMAIL_AUTH`：

- 管理员密钥：也就是 Worker 环境变量里的 `EMAIL_AUTH`，创建地址不扣用户额度。
- 用户 API Key：用户在网页里生成，创建地址会扣该用户 1 次额度，并自动归属到他的邮箱池。

## 网页接口

| 功能 | 方法 | 路径 |
| --- | --- | --- |
| 注册 | `POST` | `/app/api/register` |
| 统一登录 | `POST` | `/auth/login` |
| 用户登录（兼容） | `POST` | `/app/api/login` |
| 当前用户 | `GET` | `/app/api/me` |
| 兑换/激活更多次数 | `POST` | `/app/api/redeem` |
| 地址列表 | `GET` | `/app/api/addresses` |
| API Key 列表 | `GET` | `/app/api/api_keys` |
| 创建 API Key | `POST` | `/app/api/api_keys` |
| 吊销 API Key | `POST` | `/app/api/api_keys/revoke` |
| 创建 1 个地址 | `POST` | `/app/api/addresses` |
| 批量创建地址 | `POST` | `/app/api/addresses/batch` |
| 用户邮件列表 | `GET` | `/app/api/mails?address=xxx@domain` |
| 用户邮件详情 | `GET` | `/app/api/mail/{id}` |
| 管理员登录（兼容） | `POST` | `/admin/login` |
| 当前管理员 | `GET` | `/admin/me` |
| 管理员生成激活码 | `POST` | `/admin/redeem_codes` |

`/app/api/*` 的用户接口可以用两种 Bearer：

- 网页登录返回的用户 session token。
- 用户在网页里生成的 `smk_...` API Key。

也就是说，买家可以直接用自己的 API Key 查自己的邮箱池：

```bash
curl "https://你的-worker-域名/app/api/addresses" ^
  -H "Authorization: Bearer smk_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

curl "https://你的-worker-域名/app/api/mails?address=001@tyrlink.dpdns.org&limit=20&offset=0" ^
  -H "Authorization: Bearer smk_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

curl "https://你的-worker-域名/app/api/mail/mail_xxx" ^
  -H "Authorization: Bearer smk_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
```

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
| `EMAIL_AUTH` | `change-me-admin-secret` | 兼容旧脚本的管理员密钥，也作为默认 JWT fallback |
| `JWT_SECRET` | `change-me-jwt-secret` | JWT 签名密钥；不填时会 fallback 到 `EMAIL_AUTH` |
| `ADMIN_USERNAME` | `admin` | 管理员网页登录账号；不填默认 `admin` |
| `ADMIN_PASSWORD` | `change-me-admin-password` | 管理员网页登录密码；不填会 fallback 到 `EMAIL_AUTH` |
| `EMAIL_DOMAIN` | `tyrlink.dpdns.org` | 默认收信域名 |
| `EMAIL_DOMAINS` | `tyrlink.dpdns.org,example.com` | 多域名可选，逗号分隔 |
| `ALLOW_REGISTRATION` | `true` | 是否允许公开注册；想只给邀请用户就设 `false` |
| `REQUIRE_REGISTER_CODE` | `true` | 注册时是否必须填写激活码；不填默认 `true` |
| `MAX_BATCH_CREATE` | `100` | 单次批量创建上限 |
| `RETENTION_HOURS` | `0` | 邮件保留小时数；`0` 表示不自动清理 |
| `MAX_RAW_BYTES` | `2097152` | 单封 raw 邮件最大字节数，默认 2MB |

## D1 建表

Worker 首次 API 请求会自动建表和迁移 `addresses.user_id`。如果你想手动建，也可以在 D1 控制台运行 `schema.sql`。

## 给别人使用的流程

1. 你在网页后台绑定 D1、R2、变量并部署。
2. 你打开 Worker 根路径 `/`，在同一个登录框用 `ADMIN_USERNAME` / `ADMIN_PASSWORD` 进入管理员后台。
3. 生成一个 50 次或 100 次激活码。
4. 买家注册账号时填写激活码，注册成功后直接得到次数。
5. 买家在“脚本 API 密钥”里生成自己的用户 API Key。
6. 买家可以在网页里批量创建邮箱，也可以把 API Key 填进脚本 `.env` 自动创建。
7. 买家在网页或 API 里查看这些邮箱收到的邮件和验证码。

## 买家脚本 `.env`

买家的 `.env` 不要填你的管理员密钥，填他自己网页里生成的用户 API Key：

```ini
EMAIL_API=https://你的-worker-域名
EMAIL_AUTH=smk_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
EMAIL_DOMAIN=tyrlink.dpdns.org
NV_PASSWORD=买家的 NVIDIA 密码
```

调用流程和 `EMAIL_API_SPEC.md` 一样：

```text
1. POST /admin/new_address
   Header: x-admin-auth: 用户 API Key
   Body: {"name":"001","domain":"tyrlink.dpdns.org","enablePrefix":false}
   -> 返回 { address, jwt }，并扣该用户 1 次额度

2. GET /api/mails?limit=5&offset=0
   Header: Authorization: Bearer {jwt}

3. GET /api/mail/{id}
   Header: Authorization: Bearer {jwt}
   -> 返回 { raw }
```

如果买家的脚本想“查整个邮箱池”，不用走单邮箱 JWT，可以直接用用户 API Key：

```text
GET /app/api/addresses
Authorization: Bearer 用户 API Key

GET /app/api/mails?address=某个已拥有邮箱&limit=20&offset=0
Authorization: Bearer 用户 API Key

GET /app/api/mail/{id}
Authorization: Bearer 用户 API Key
```

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
EMAIL_AUTH=管理员密钥或买家自己的用户 API Key
EMAIL_DOMAIN=tyrlink.dpdns.org
NV_PASSWORD=你的 NVIDIA 密码
```

`/api/mail/{id}` 返回的 `raw` 是完整原始邮件文本，脚本可以继续用正则提取 `123-456` 这类验证码。
