const te = new TextEncoder();
const JSON_HEADERS = { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' };

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), { status, headers: { ...JSON_HEADERS, ...headers } });
}
function html(body, status = 200) {
  return new Response(body, { status, headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' } });
}
function b64url(bytes) {
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function randomToken(n = 32) {
  const bytes = new Uint8Array(n);
  crypto.getRandomValues(bytes);
  return b64url(bytes);
}
async function sha256(value) {
  return b64url(new Uint8Array(await crypto.subtle.digest('SHA-256', te.encode(value))));
}
async function pbkdf2(password, salt) {
  const key = await crypto.subtle.importKey('raw', te.encode(password), { name: 'PBKDF2' }, false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: te.encode(salt), iterations: 210000 }, key, 256);
  return b64url(new Uint8Array(bits));
}
function cookie(name, value, maxAge = 60 * 60 * 24 * 30) {
  return `${name}=${value}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`;
}
function getCookie(request, name) {
  const raw = request.headers.get('cookie') || '';
  for (const part of raw.split(';')) {
    const [key, ...rest] = part.trim().split('=');
    if (key === name) return rest.join('=');
  }
  return null;
}
function cleanUsername(value) {
  return String(value || '').trim().replace(/[<>\u0000-\u001f]/g, '').slice(0, 32);
}
function cleanSlug(value) {
  return String(value || '').trim().toLowerCase().replace(/[^a-z0-9-]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 64);
}
async function bodyJson(request) {
  try { return await request.json(); } catch { return {}; }
}

async function ensureSchema(env) {
  await env.DB.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL UNIQUE COLLATE NOCASE,
      password_salt TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'user',
      total_seconds INTEGER NOT NULL DEFAULT 0,
      created_at INTEGER NOT NULL,
      last_seen INTEGER
    );
    CREATE TABLE IF NOT EXISTS sessions (
      token_hash TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL,
      created_at INTEGER NOT NULL,
      last_seen INTEGER NOT NULL,
      current_game_id INTEGER,
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS games (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      slug TEXT NOT NULL UNIQUE,
      title TEXT NOT NULL,
      description TEXT NOT NULL DEFAULT '',
      visible INTEGER NOT NULL DEFAULT 1,
      kind TEXT NOT NULL DEFAULT 'r2',
      object_key TEXT,
      launch_path TEXT,
      play_seconds INTEGER NOT NULL DEFAULT 0,
      created_at INTEGER NOT NULL,
      updated_at INTEGER NOT NULL
    );
  `);

  const adminName = env.ADMIN_USERNAME || 'Alu';
  const admin = await env.DB.prepare('SELECT id FROM users WHERE username=?').bind(adminName).first();
  if (!admin) {
    const now = Date.now();
    await env.DB.prepare('INSERT INTO users(username,password_salt,password_hash,role,created_at,last_seen) VALUES(?,?,?,?,?,?)')
      .bind(adminName, env.ADMIN_PASSWORD_SALT, env.ADMIN_PASSWORD_HASH, 'admin', now, now).run();
  }

  const robot = await env.DB.prepare("SELECT id FROM games WHERE slug='robot-battle'").first();
  if (!robot) {
    const now = Date.now();
    await env.DB.prepare('INSERT INTO games(slug,title,description,visible,kind,launch_path,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)')
      .bind('robot-battle', '机器狗大战', 'AIDC 机房多人在线机器狗对战，支持公网房间、移动端操作和实时网络时延显示。', 1, 'proxy', '/play/robot-battle/', now, now).run();
  }
}

async function auth(request, env) {
  const token = getCookie(request, 'alu_session');
  if (!token) return null;
  const tokenHash = await sha256(token);
  return env.DB.prepare(`
    SELECT u.id,u.username,u.role,u.total_seconds,u.password_salt,u.password_hash,
           s.token_hash,s.last_seen,s.current_game_id
    FROM sessions s JOIN users u ON u.id=s.user_id
    WHERE s.token_hash=?
  `).bind(tokenHash).first();
}

async function createSession(userId, env) {
  const token = randomToken(32);
  const tokenHash = await sha256(token);
  const now = Date.now();
  await env.DB.prepare('INSERT INTO sessions(token_hash,user_id,created_at,last_seen) VALUES(?,?,?,?)')
    .bind(tokenHash, userId, now, now).run();
  return token;
}

async function proxyRobot(request, env, pathname) {
  let suffix = pathname.startsWith('/play/robot-battle') ? pathname.slice('/play/robot-battle'.length) : pathname;
  if (!suffix) suffix = '/';
  const source = new URL(request.url);
  const target = new URL(suffix + source.search, env.ROBOT_BATTLE_ORIGIN);
  const headers = new Headers(request.headers);
  headers.delete('host');
  const init = { method: request.method, headers, redirect: 'manual' };
  if (!['GET', 'HEAD'].includes(request.method)) init.body = request.body;
  return fetch(new Request(target, init));
}

async function serveUploadedGame(game, env) {
  if (!game.object_key) return html('<h1>游戏文件不存在</h1>', 404);
  const object = await env.GAMES.get(game.object_key);
  if (!object) return html('<h1>游戏文件不存在</h1>', 404);
  return new Response(object.body, {
    headers: {
      'content-type': object.httpMetadata?.contentType || 'text/html; charset=utf-8',
      'cache-control': 'no-store',
      'x-content-type-options': 'nosniff'
    }
  });
}

async function api(request, env, url) {
  const path = url.pathname;

  if (path === '/api/register' && request.method === 'POST') {
    const body = await bodyJson(request);
    const username = cleanUsername(body.username);
    const password = String(body.password || '');
    if (username.length < 2 || password.length < 8) return json({ ok: false, message: '用户名至少2位，密码至少8位' }, 400);
    if (username.toLowerCase() === String(env.ADMIN_USERNAME || 'Alu').toLowerCase()) return json({ ok: false, message: '该用户名已保留' }, 409);
    if (await env.DB.prepare('SELECT id FROM users WHERE username=?').bind(username).first()) return json({ ok: false, message: '用户名已存在' }, 409);
    const salt = randomToken(16);
    const hash = await pbkdf2(password, salt);
    const now = Date.now();
    const result = await env.DB.prepare('INSERT INTO users(username,password_salt,password_hash,role,created_at,last_seen) VALUES(?,?,?,?,?,?)')
      .bind(username, salt, hash, 'user', now, now).run();
    const token = await createSession(result.meta.last_row_id, env);
    return json({ ok: true }, 200, { 'set-cookie': cookie('alu_session', token) });
  }

  if (path === '/api/login' && request.method === 'POST') {
    const body = await bodyJson(request);
    const username = cleanUsername(body.username);
    const password = String(body.password || '');
    const user = await env.DB.prepare('SELECT * FROM users WHERE username=?').bind(username).first();
    if (!user || await pbkdf2(password, user.password_salt) !== user.password_hash) return json({ ok: false, message: '用户名或密码错误' }, 401);
    const token = await createSession(user.id, env);
    await env.DB.prepare('UPDATE users SET last_seen=? WHERE id=?').bind(Date.now(), user.id).run();
    return json({ ok: true, role: user.role }, 200, { 'set-cookie': cookie('alu_session', token) });
  }

  if (path === '/api/logout' && request.method === 'POST') {
    const token = getCookie(request, 'alu_session');
    if (token) await env.DB.prepare('DELETE FROM sessions WHERE token_hash=?').bind(await sha256(token)).run();
    return json({ ok: true }, 200, { 'set-cookie': cookie('alu_session', '', 0) });
  }

  const me = await auth(request, env);
  if (!me) return json({ ok: false, message: '请先登录' }, 401);

  if (path === '/api/me') {
    return json({ ok: true, user: { id: me.id, username: me.username, role: me.role, total_seconds: me.total_seconds } });
  }

  if (path === '/api/change-password' && request.method === 'POST') {
    const body = await bodyJson(request);
    const oldPassword = String(body.old_password || '');
    const newPassword = String(body.new_password || '');
    if (newPassword.length < 8) return json({ ok: false, message: '新密码至少8位' }, 400);
    if (await pbkdf2(oldPassword, me.password_salt) !== me.password_hash) return json({ ok: false, message: '当前密码错误' }, 403);
    const salt = randomToken(16);
    const hash = await pbkdf2(newPassword, salt);
    await env.DB.prepare('UPDATE users SET password_salt=?,password_hash=? WHERE id=?').bind(salt, hash, me.id).run();
    return json({ ok: true });
  }

  if (path === '/api/games') {
    const rows = await env.DB.prepare(`SELECT id,slug,title,description,visible,kind,launch_path,play_seconds,updated_at FROM games ${me.role === 'admin' ? '' : 'WHERE visible=1'} ORDER BY id`).all();
    return json({ ok: true, games: rows.results });
  }

  if (path === '/api/heartbeat' && request.method === 'POST') {
    const body = await bodyJson(request);
    const gameId = Number(body.game_id) || null;
    const now = Date.now();
    const previous = Number(me.last_seen || now);
    const delta = Math.max(0, Math.min(45, Math.floor((now - previous) / 1000)));
    const statements = [
      env.DB.prepare('UPDATE sessions SET last_seen=?,current_game_id=? WHERE token_hash=?').bind(now, gameId, me.token_hash),
      env.DB.prepare('UPDATE users SET last_seen=?,total_seconds=total_seconds+? WHERE id=?').bind(now, delta, me.id)
    ];
    if (gameId) statements.push(env.DB.prepare('UPDATE games SET play_seconds=play_seconds+? WHERE id=?').bind(delta, gameId));
    await env.DB.batch(statements);
    const updated = await env.DB.prepare('SELECT total_seconds FROM users WHERE id=?').bind(me.id).first();
    return json({ ok: true, total_seconds: updated?.total_seconds || 0 });
  }

  if (me.role !== 'admin') return json({ ok: false, message: '管理员权限不足' }, 403);

  if (path === '/api/admin/stats') {
    const users = (await env.DB.prepare('SELECT id,username,role,total_seconds,created_at,last_seen FROM users ORDER BY last_seen DESC').all()).results;
    const games = (await env.DB.prepare('SELECT id,title,slug,description,visible,kind,launch_path,play_seconds,updated_at FROM games ORDER BY id').all()).results;
    const row = await env.DB.prepare('SELECT COUNT(DISTINCT user_id) AS c FROM sessions WHERE last_seen>?').bind(Date.now() - 60000).first();
    return json({ ok: true, online: row?.c || 0, users, games });
  }

  if (path === '/api/admin/game' && request.method === 'POST') {
    const body = await bodyJson(request);
    const id = Number(body.id) || 0;
    const title = String(body.title || '').trim().slice(0, 80);
    const slug = cleanSlug(body.slug || title);
    const description = String(body.description || '').trim().slice(0, 500);
    const visible = body.visible ? 1 : 0;
    if (!title || !slug) return json({ ok: false, message: '游戏名和 Slug 不能为空' }, 400);
    const duplicate = await env.DB.prepare('SELECT id FROM games WHERE slug=? AND id<>?').bind(slug, id).first();
    if (duplicate) return json({ ok: false, message: 'Slug 已存在' }, 409);
    const now = Date.now();
    if (id) {
      await env.DB.prepare('UPDATE games SET title=?,slug=?,description=?,visible=?,updated_at=? WHERE id=?').bind(title, slug, description, visible, now, id).run();
    } else {
      await env.DB.prepare('INSERT INTO games(slug,title,description,visible,kind,created_at,updated_at) VALUES(?,?,?,?,?,?,?)').bind(slug, title, description, visible, 'r2', now, now).run();
    }
    return json({ ok: true });
  }

  const uploadMatch = path.match(/^\/api\/admin\/games\/(\d+)\/upload$/);
  if (uploadMatch && request.method === 'POST') {
    const id = Number(uploadMatch[1]);
    const game = await env.DB.prepare('SELECT * FROM games WHERE id=?').bind(id).first();
    if (!game) return json({ ok: false, message: '游戏不存在' }, 404);
    if (game.kind === 'proxy') return json({ ok: false, message: '代理型核心游戏不通过此入口上传' }, 400);
    const form = await request.formData();
    const file = form.get('file');
    if (!(file instanceof File)) return json({ ok: false, message: '请选择 HTML 文件' }, 400);
    if (!/\.html?$/i.test(file.name)) return json({ ok: false, message: '仅支持 HTML 文件' }, 400);
    if (file.size > 20 * 1024 * 1024) return json({ ok: false, message: '单个 HTML 暂限制 20MB 以内' }, 413);
    const key = `games/${id}/index.html`;
    await env.GAMES.put(key, await file.arrayBuffer(), { httpMetadata: { contentType: 'text/html; charset=utf-8' } });
    await env.DB.prepare("UPDATE games SET kind='r2',object_key=?,launch_path=?,updated_at=? WHERE id=?")
      .bind(key, `/games/${id}/`, Date.now(), id).run();
    return json({ ok: true, launch_path: `/games/${id}/` });
  }

  const visibilityMatch = path.match(/^\/api\/admin\/games\/(\d+)\/visibility$/);
  if (visibilityMatch && request.method === 'POST') {
    const body = await bodyJson(request);
    await env.DB.prepare('UPDATE games SET visible=?,updated_at=? WHERE id=?').bind(body.visible ? 1 : 0, Date.now(), Number(visibilityMatch[1])).run();
    return json({ ok: true });
  }

  const deleteMatch = path.match(/^\/api\/admin\/games\/(\d+)$/);
  if (deleteMatch && request.method === 'DELETE') {
    const id = Number(deleteMatch[1]);
    const game = await env.DB.prepare('SELECT * FROM games WHERE id=?').bind(id).first();
    if (!game) return json({ ok: false, message: '游戏不存在' }, 404);
    if (game.slug === 'robot-battle') return json({ ok: false, message: '核心游戏不可删除，可设置为不可见' }, 400);
    if (game.object_key) await env.GAMES.delete(game.object_key);
    await env.DB.prepare('DELETE FROM games WHERE id=?').bind(id).run();
    return json({ ok: true });
  }

  return json({ ok: false, message: '接口不存在' }, 404);
}

export default {
  async fetch(request, env) {
    try {
      await ensureSchema(env);
      const url = new URL(request.url);
      const path = url.pathname;

      if (path.startsWith('/socket.io/')) return proxyRobot(request, env, path);
      if (path.startsWith('/play/robot-battle')) return proxyRobot(request, env, path);
      if (['/manifest.webmanifest', '/icon-192.png', '/icon-512.png'].includes(path)) return proxyRobot(request, env, path);
      if (path.startsWith('/api/')) return api(request, env, url);

      if (path.startsWith('/games/')) {
        const me = await auth(request, env);
        if (!me) return Response.redirect(new URL('/', url), 302);
        const match = path.match(/^\/games\/(\d+)/);
        if (!match) return html('<h1>Not found</h1>', 404);
        const game = await env.DB.prepare('SELECT * FROM games WHERE id=?').bind(Number(match[1])).first();
        if (!game || (!game.visible && me.role !== 'admin')) return html('<h1>游戏不可用</h1>', 404);
        return serveUploadedGame(game, env);
      }

      const downloadMatch = path.match(/^\/admin\/download\/(\d+)$/);
      if (downloadMatch) {
        const me = await auth(request, env);
        if (!me || me.role !== 'admin') return html('Forbidden', 403);
        const game = await env.DB.prepare('SELECT * FROM games WHERE id=?').bind(Number(downloadMatch[1])).first();
        if (!game?.object_key) return html('Not found', 404);
        const object = await env.GAMES.get(game.object_key);
        if (!object) return html('Not found', 404);
        return new Response(object.body, { headers: { 'content-type': 'text/html; charset=utf-8', 'content-disposition': `attachment; filename="${game.slug || 'game'}.html"` } });
      }

      return env.ASSETS.fetch(request);
    } catch (error) {
      console.error(error);
      return json({ ok: false, message: error?.message || String(error) }, 500);
    }
  }
};
