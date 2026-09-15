# ALU PLAY · Cloudflare

ALU PLAY 的 Cloudflare 版本。门户、账号、管理员后台和统计运行在 Cloudflare Workers；用户/会话/游戏元数据存入 D1；管理员上传的单文件 HTML 游戏存入 R2。

## 已实现

- 用户注册、登录、退出、密码显示/隐藏
- 管理员账号 `Alu`
- 管理员新增游戏、编辑名称/Slug/描述、上下架
- 管理员上传/覆盖 HTML 游戏、下载 HTML、删除普通游戏
- 在线用户数量、每个用户累计在线时长、游戏累计时长字段
- 首款核心游戏“机器狗大战”入口
- Cloudflare 反向代理现有 Railway Socket.IO 服务，保留公网多人联机
- D1 / R2 首次部署自动创建并绑定

## Cloudflare 部署

本项目使用 Wrangler 4.45+ 的自动资源创建能力。第一次部署时，配置中的 `DB` 和 `GAMES` binding 会自动创建 D1 数据库和 R2 bucket。

### 方式 A：Cloudflare Dashboard + GitHub

1. Cloudflare Dashboard → Workers & Pages → Create application → Import a repository。
2. 选择 GitHub 仓库 `Alumgs/Alu_Game_Center`。
3. Production branch 选择 `main`。
4. Build command：`npm install`
5. Deploy command：`npx wrangler deploy`
6. 保存并部署。首次部署会自动创建并绑定 D1/R2。
7. 部署完成后先使用 `*.workers.dev` 地址测试登录、后台、上传 HTML 和机器狗大战。
8. 再在 Worker → Settings → Domains & Routes 绑定你自己可控 DNS 的自定义域名。

### 方式 B：Codex / Cloudflare 插件

仓库已经可以直接部署。让 Codex 在本仓库执行 Cloudflare deploy 即可，不需要手工创建 D1 或 R2。

## 管理员

管理员用户名固定为 `Alu`。初始密码只用于首次登录，请上线后立即通过页面右上角“修改密码”更新。

## 架构

```text
Browser
  │
  ▼
Cloudflare Worker (ALU PLAY)
  ├─ Static Assets: 门户页面
  ├─ D1: users / sessions / games
  ├─ R2: 管理员上传的 HTML 游戏
  └─ /play/robot-battle + /socket.io/*
           │
           ▼
Railway: AIDC Robot Battle V13 Socket.IO
```

后续若要完全移除 Railway，可把多人联机房间状态迁移到 Cloudflare Durable Objects + WebSocket。
