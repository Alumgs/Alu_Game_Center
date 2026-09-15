const te = new TextEncoder();
const td = new TextDecoder();

const JSON_HEADERS = { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' };
const HTML_HEADERS = { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' };

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), { status, headers: { ...JSON_HEADERS, ...headers } });
}
function html(body, status = 200) { return new Response(body, { status, headers: HTML_HEADERS }); }
function b64url(bytes) { return btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); }
function randomToken(n = 32) { const b = new Uint8Array(n); crypto.getRandomValues(b); return b64url(b); }
async function sha256(s) { return b64url(new Uint8Array(await crypto.subtle.digest('SHA-256', te.encode(s)))); }
async function pbkdf2(password, salt) {
  const key = await crypto.subtle.importKey('raw', te.encode(password), { name: 'PBKDF2' }, false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: te.encode(salt), iterations: 210000 }, key, 256);
  return b64url(new Uint8Array(bits));
}
function cookie(name, value, maxAge = 60 * 60 * 24 * 30) {
  return `${name}=${value}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`;
}
function getCookie(req, name) {
  const raw = req.headers.get('cookie') || '';
  for (const part of raw.split(';')) { const [k, ...v] = part.trim().split('='); if (k === name) return v.join('='); }
  return null;
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
  const admin = await env.DB.prepare('SELECT id FROM users WHERE username = ?').bind(env.ADMIN_USERNAME || 'Alu').first();
  if (!admin) {
    await env.DB.prepare('INSERT INTO users(username,password_salt,password_hash,role,created_at,last_seen) VALUES(?,?,?,?,?,?)')
      .bind(env.ADMIN_USERNAME || 'Alu', env.ADMIN_PASSWORD_SALT, env.ADMIN_PASSWORD_HASH, 'admin', Date.now(), Date.now()).run();
  }
  const rb = await env.DB.prepare("SELECT id FROM games WHERE slug='robot-battle'").first();
  if (!rb) {
    const now = Date.now();
    await env.DB.prepare('INSERT INTO games(slug,title,description,visible,kind,launch_path,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)')
      .bind('robot-battle', '机器狗大战', 'AIDC 机房多人在线机器狗对战，支持公网房间、移动端操作和实时网络时延显示。', 1, 'proxy', '/play/robot-battle/', now, now).run();
  }
}
async function auth(req, env) {
  const token = getCookie(req, 'alu_session');
  if (!token) return null;
  const th = await sha256(token);
  const row = await env.DB.prepare(`SELECT u.id,u.username,u.role,u.total_seconds,s.token_hash,s.last_seen,s.current_game_id
    FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=?`).bind(th).first();
  if (!row) return null;
  return row;
}
async function createSession(userId, env) {
  const token = randomToken(32); const th = await sha256(token); const now = Date.now();
  await env.DB.prepare('INSERT INTO sessions(token_hash,user_id,created_at,last_seen) VALUES(?,?,?,?)').bind(th, userId, now, now).run();
  return token;
}
async function bodyJson(req) { try { return await req.json(); } catch { return {}; } }
function cleanUsername(v) { return String(v || '').trim().replace(/[<>\u0000-\u001f]/g, '').slice(0, 32); }
function cleanSlug(v) { return String(v || '').trim().toLowerCase().replace(/[^a-z0-9-]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 64); }

async function proxyRobot(request, env, pathname) {
  let suffix = pathname.startsWith('/play/robot-battle') ? pathname.slice('/play/robot-battle'.length) : pathname;
  if (!suffix) suffix = '/';
  const src = new URL(request.url);
  const target = new URL(suffix + src.search, env.ROBOT_BATTLE_ORIGIN);
  const headers = new Headers(request.headers);
  headers.set('host', target.host);
  const proxied = new Request(target, { method: request.method, headers, body: ['GET','HEAD'].includes(request.method) ? undefined : request.body, redirect: 'manual' });
  return fetch(proxied);
}

async function serveUploadedGame(game, env) {
  if (!game.object_key) return html('<h1>游戏文件不存在</h1>', 404);
  const obj = await env.GAMES.get(game.object_key);
  if (!obj) return html('<h1>游戏文件不存在</h1>', 404);
  return new Response(obj.body, { headers: { 'content-type': obj.httpMetadata?.contentType || 'text/html; charset=utf-8', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' } });
}

async function api(request, env, url) {
  const p = url.pathname;
  if (p === '/api/register' && request.method === 'POST') {
    const b = await bodyJson(request); const username = cleanUsername(b.username); const password = String(b.password || '');
    if (username.length < 2 || password.length < 8) return json({ ok:false, message:'用户名至少2位，密码至少8位' }, 400);
    if (username.toLowerCase() === String(env.ADMIN_USERNAME || 'Alu').toLowerCase()) return json({ ok:false, message:'该用户名已保留' }, 409);
    const exists = await env.DB.prepare('SELECT id FROM users WHERE username=?').bind(username).first(); if (exists) return json({ok:false,message:'用户名已存在'},409);
    const salt = randomToken(16); const hash = await pbkdf2(password, salt); const now = Date.now();
    const r = await env.DB.prepare('INSERT INTO users(username,password_salt,password_hash,role,created_at,last_seen) VALUES(?,?,?,?,?,?)').bind(username,salt,hash,'user',now,now).run();
    const token = await createSession(r.meta.last_row_id, env);
    return json({ok:true},200,{'set-cookie':cookie('alu_session',token)});
  }
  if (p === '/api/login' && request.method === 'POST') {
    const b=await bodyJson(request); const username=cleanUsername(b.username); const password=String(b.password||'');
    const u=await env.DB.prepare('SELECT * FROM users WHERE username=?').bind(username).first();
    if(!u || await pbkdf2(password,u.password_salt)!==u.password_hash) return json({ok:false,message:'用户名或密码错误'},401);
    const token=await createSession(u.id,env); await env.DB.prepare('UPDATE users SET last_seen=? WHERE id=?').bind(Date.now(),u.id).run();
    return json({ok:true,role:u.role},200,{'set-cookie':cookie('alu_session',token)});
  }
  if (p === '/api/logout' && request.method === 'POST') {
    const token=getCookie(request,'alu_session'); if(token) await env.DB.prepare('DELETE FROM sessions WHERE token_hash=?').bind(await sha256(token)).run();
    return json({ok:true},200,{'set-cookie':cookie('alu_session','',0)});
  }
  const me=await auth(request,env); if(!me) return json({ok:false,message:'请先登录'},401);
  if (p === '/api/me') return json({ok:true,user:{id:me.id,username:me.username,role:me.role,total_seconds:me.total_seconds}});
  if (p === '/api/games') {
    const admin=me.role==='admin'; const rows=await env.DB.prepare(`SELECT id,slug,title,description,visible,kind,launch_path,play_seconds,updated_at FROM games ${admin?'':'WHERE visible=1'} ORDER BY id`).all();
    return json({ok:true,games:rows.results});
  }
  if (p === '/api/heartbeat' && request.method === 'POST') {
    const b=await bodyJson(request); const gameId=Number(b.game_id)||null; const now=Date.now(); const prev=Number(me.last_seen||now); const delta=Math.max(0,Math.min(45,Math.floor((now-prev)/1000)));
    await env.DB.batch([
      env.DB.prepare('UPDATE sessions SET last_seen=?,current_game_id=? WHERE token_hash=?').bind(now,gameId,me.token_hash),
      env.DB.prepare('UPDATE users SET last_seen=?,total_seconds=total_seconds+? WHERE id=?').bind(now,delta,me.id),
      gameId?env.DB.prepare('UPDATE games SET play_seconds=play_seconds+? WHERE id=?').bind(delta,gameId):env.DB.prepare('SELECT 1')
    ]);
    return json({ok:true});
  }
  if (me.role!=='admin') return json({ok:false,message:'管理员权限不足'},403);
  if (p === '/api/admin/stats') {
    const users=(await env.DB.prepare('SELECT id,username,role,total_seconds,created_at,last_seen FROM users ORDER BY last_seen DESC').all()).results;
    const games=(await env.DB.prepare('SELECT id,title,slug,visible,kind,play_seconds,updated_at FROM games ORDER BY id').all()).results;
    const online=(await env.DB.prepare('SELECT COUNT(*) c FROM sessions WHERE last_seen>?').bind(Date.now()-60000).first()).c;
    return json({ok:true,online,users,games});
  }
  if (p === '/api/admin/game' && request.method === 'POST') {
    const b=await bodyJson(request); const id=Number(b.id)||0; const title=String(b.title||'').trim().slice(0,80); const slug=cleanSlug(b.slug||title); const description=String(b.description||'').trim().slice(0,500); const visible=b.visible?1:0;
    if(!title||!slug) return json({ok:false,message:'游戏名和slug不能为空'},400);
    const now=Date.now();
    if(id) await env.DB.prepare('UPDATE games SET title=?,slug=?,description=?,visible=?,updated_at=? WHERE id=?').bind(title,slug,description,visible,now,id).run();
    else await env.DB.prepare('INSERT INTO games(slug,title,description,visible,kind,created_at,updated_at) VALUES(?,?,?,?,?,?,?)').bind(slug,title,description,visible,'r2',now,now).run();
    return json({ok:true});
  }
  const uploadMatch=p.match(/^\/api\/admin\/games\/(\d+)\/upload$/);
  if(uploadMatch && request.method==='POST') {
    const id=Number(uploadMatch[1]); const g=await env.DB.prepare('SELECT * FROM games WHERE id=?').bind(id).first(); if(!g) return json({ok:false,message:'游戏不存在'},404);
    const form=await request.formData(); const file=form.get('file'); if(!(file instanceof File)) return json({ok:false,message:'请选择HTML文件'},400);
    if(!/\.html?$/i.test(file.name)) return json({ok:false,message:'仅支持HTML文件'},400);
    const key=`games/${id}/index.html`; await env.GAMES.put(key,await file.arrayBuffer(),{httpMetadata:{contentType:'text/html; charset=utf-8'}});
    await env.DB.prepare("UPDATE games SET kind='r2',object_key=?,launch_path=?,updated_at=? WHERE id=?").bind(key,`/games/${id}/`,Date.now(),id).run();
    return json({ok:true,launch_path:`/games/${id}/`});
  }
  const visMatch=p.match(/^\/api\/admin\/games\/(\d+)\/visibility$/);
  if(visMatch && request.method==='POST') { const b=await bodyJson(request); await env.DB.prepare('UPDATE games SET visible=?,updated_at=? WHERE id=?').bind(b.visible?1:0,Date.now(),Number(visMatch[1])).run(); return json({ok:true}); }
  const delMatch=p.match(/^\/api\/admin\/games\/(\d+)$/);
  if(delMatch && request.method==='DELETE') {
    const id=Number(delMatch[1]); const g=await env.DB.prepare('SELECT * FROM games WHERE id=?').bind(id).first(); if(!g) return json({ok:false,message:'游戏不存在'},404);
    if(g.slug==='robot-battle') return json({ok:false,message:'核心游戏请勿删除，可设为不可见'},400);
    if(g.object_key) await env.GAMES.delete(g.object_key); await env.DB.prepare('DELETE FROM games WHERE id=?').bind(id).run(); return json({ok:true});
  }
  return json({ok:false,message:'接口不存在'},404);
}

function page() {
return `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>ALU PLAY</title><style>
:root{color-scheme:dark;--bg:#07111b;--panel:#0d1b2a;--line:#21364b;--text:#eef6fb;--muted:#8ea6b8;--accent:#72e0cd;--danger:#ff776d}*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 20% 0,#16344b 0,transparent 35%),var(--bg);font:15px/1.5 system-ui,-apple-system,"Microsoft Yahei",sans-serif;color:var(--text)}button,input,textarea{font:inherit}button{cursor:pointer}.shell{max-width:1180px;margin:auto;padding:28px}.brand{display:flex;align-items:center;justify-content:space-between;margin-bottom:26px}.brand h1{margin:0;font-size:24px;letter-spacing:.14em}.brand small{color:var(--muted)}.hero{display:grid;grid-template-columns:1.25fr .75fr;gap:24px;min-height:72vh;align-items:center}.copy h2{font-size:clamp(42px,7vw,84px);line-height:.92;margin:12px 0;letter-spacing:-.055em}.copy p{max-width:610px;color:var(--muted);font-size:18px}.chips{display:flex;gap:10px;flex-wrap:wrap;margin-top:24px}.chip{border:1px solid var(--line);padding:7px 11px;border-radius:999px;color:#cce5ee}.card,.game{border:1px solid var(--line);background:#0b1825d9;border-radius:18px;padding:22px;box-shadow:0 18px 60px #0006}.card h3{margin-top:0}.field{margin:12px 0}.field label{display:block;color:var(--muted);font-size:12px;margin-bottom:6px}.field input,.field textarea{width:100%;border:1px solid var(--line);background:#08131e;color:var(--text);border-radius:10px;padding:11px}.row{display:flex;gap:8px;align-items:center}.btn{border:1px solid var(--line);background:#102337;color:var(--text);border-radius:10px;padding:10px 14px}.btn.primary{background:var(--accent);color:#062522;border-color:var(--accent);font-weight:750}.btn.danger{color:#ffd8d4;border-color:#7f403b}.muted{color:var(--muted)}#app{display:none}.topbar{display:flex;justify-content:space-between;gap:16px;align-items:center;margin-bottom:22px}.games{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:16px}.game h3{margin:0 0 8px}.game p{color:var(--muted);min-height:44px}.meta{font-size:12px;color:var(--muted);margin:10px 0 16px}.admin{margin-top:28px}.admin-grid{display:grid;grid-template-columns:1fr 1fr;gap:16px}.list{display:grid;gap:8px}.item{border:1px solid var(--line);border-radius:10px;padding:10px}.tabs{display:flex;gap:8px;margin-bottom:16px}.hidden{display:none!important}@media(max-width:760px){.hero,.admin-grid{grid-template-columns:1fr}.copy h2{font-size:50px}.shell{padding:18px}.hero{align-items:start}.topbar{align-items:flex-start;flex-direction:column}}</style></head><body><div class="shell"><div class="brand"><h1>ALU PLAY</h1><small>SMALL GAMES. BIG WORLDS.</small></div>
<section id="auth" class="hero"><div class="copy"><div class="muted">独立游戏空间</div><h2>好玩的世界，<br>一起进入。</h2><p>你的私人游戏库，也是与朋友相遇的地方。从一场机房大战，开始今天的冒险。</p><div class="chips"><span class="chip">01 / 多人在线</span><span class="chip">02 / 沉浸探索</span><span class="chip">03 / 自由实验</span></div></div><div class="card"><h3 id="authTitle">欢迎回来</h3><div class="tabs"><button class="btn primary" id="loginTab">登录</button><button class="btn" id="registerTab">注册</button></div><div class="field"><label>用户名</label><input id="username" autocomplete="username"></div><div class="field"><label>密码</label><div class="row"><input id="password" type="password" autocomplete="current-password"><button class="btn" id="showPwd">显示</button></div></div><button class="btn primary" id="submitAuth">登录游戏库</button><p id="authMsg" class="muted"></p><small class="muted">在线时长仅统计页面在前台时的连接时长。</small></div></section>
<section id="app"><div class="topbar"><div><h2 style="margin:0">欢迎，<span id="meName"></span></h2><div class="muted">今天想玩什么？</div></div><div class="row"><span id="myTime" class="muted"></span><button class="btn" id="logout">退出</button></div></div><div id="games" class="games"></div><section id="admin" class="admin hidden"><h2>管理员后台</h2><div class="admin-grid"><div class="card"><h3>游戏库管理</h3><div class="field"><label>游戏名称</label><input id="gTitle"></div><div class="field"><label>Slug</label><input id="gSlug" placeholder="例如 my-game"></div><div class="field"><label>描述</label><textarea id="gDesc" rows="3"></textarea></div><div class="row"><label><input id="gVisible" type="checkbox" checked> 用户可见</label><button class="btn primary" id="createGame">新增游戏</button></div><div id="adminGames" class="list" style="margin-top:16px"></div></div><div class="card"><h3>运营概览</h3><div id="online" style="font-size:42px;font-weight:800">0</div><div class="muted">当前在线用户</div><div id="users" class="list" style="margin-top:16px"></div></div></div></section></section></div><script>
let mode='login',me=null,games=[];const $=id=>document.getElementById(id);const fmt=s=>{s=Number(s||0);const h=Math.floor(s/3600),m=Math.floor(s%3600/60);return h?`${h}小时${m}分`:`${m}分钟`};async function api(path,opt={}){const r=await fetch(path,{headers:{...(opt.body instanceof FormData?{}:{'content-type':'application/json'}),...(opt.headers||{})},...opt});const j=await r.json().catch(()=>({}));if(!r.ok)throw Error(j.message||'请求失败');return j}
$('showPwd').onclick=()=>{const i=$('password');i.type=i.type==='password'?'text':'password';$('showPwd').textContent=i.type==='password'?'显示':'隐藏'};$('loginTab').onclick=()=>setMode('login');$('registerTab').onclick=()=>setMode('register');function setMode(m){mode=m;$('authTitle').textContent=m==='login'?'欢迎回来':'创建账号';$('submitAuth').textContent=m==='login'?'登录游戏库':'注册并进入';$('loginTab').className='btn'+(m==='login'?' primary':'');$('registerTab').className='btn'+(m==='register'?' primary':'')}
$('submitAuth').onclick=async()=>{try{$('authMsg').textContent='处理中…';await api('/api/'+mode,{method:'POST',body:JSON.stringify({username:$('username').value,password:$('password').value})});await boot()}catch(e){$('authMsg').textContent=e.message}};$('logout').onclick=async()=>{await api('/api/logout',{method:'POST',body:'{}'});location.reload()};
async function boot(){try{const m=await api('/api/me');me=m.user;$('auth').style.display='none';$('app').style.display='block';$('meName').textContent=me.username;$('myTime').textContent='累计 '+fmt(me.total_seconds);$('admin').classList.toggle('hidden',me.role!=='admin');await loadGames();if(me.role==='admin')await loadAdmin();startHeartbeat()}catch{$('auth').style.display='grid';$('app').style.display='none'}}
async function loadGames(){games=(await api('/api/games')).games;$('games').innerHTML=games.filter(g=>g.visible||me.role==='admin').map(g=>`<article class="game"><div class="muted">${g.kind==='proxy'?'MULTIPLAYER':'HTML GAME'}</div><h3>${esc(g.title)}</h3><p>${esc(g.description||'')}</p><div class="meta">累计游玩 ${fmt(g.play_seconds)} ${g.visible?'· 已上架':'· 已隐藏'}</div><button class="btn primary" onclick="play(${g.id},'${g.launch_path||('/games/'+g.id+'/')}')">开始游戏</button></article>`).join('')}
function play(id,path){sessionStorage.setItem('alu_game',id);location.href=path}function esc(s){return String(s||'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
async function loadAdmin(){const s=await api('/api/admin/stats');$('online').textContent=s.online;$('users').innerHTML=s.users.map(u=>`<div class="item"><b>${esc(u.username)}</b> <span class="muted">${u.role}</span><div class="muted">累计 ${fmt(u.total_seconds)} · ${u.last_seen&&Date.now()-u.last_seen<60000?'在线':'离线'}</div></div>`).join('');$('adminGames').innerHTML=s.games.map(g=>`<div class="item"><b>${esc(g.title)}</b><div class="muted">${esc(g.slug)} · ${g.visible?'可见':'隐藏'}</div><div class="row" style="margin-top:8px"><button class="btn" onclick="toggleVis(${g.id},${g.visible?0:1})">${g.visible?'隐藏':'上架'}</button>${g.kind!=='proxy'?`<label class="btn">上传/更新HTML<input type="file" accept=".html,.htm,text/html" hidden onchange="uploadGame(${g.id},this.files[0])"></label><a class="btn" href="/admin/download/${g.id}" target="_blank">下载HTML</a><button class="btn danger" onclick="delGame(${g.id})">删除</button>`:''}</div></div>`).join('')}
$('createGame').onclick=async()=>{try{await api('/api/admin/game',{method:'POST',body:JSON.stringify({title:$('gTitle').value,slug:$('gSlug').value,description:$('gDesc').value,visible:$('gVisible').checked})});$('gTitle').value=$('gSlug').value=$('gDesc').value='';await loadGames();await loadAdmin()}catch(e){alert(e.message)}};async function toggleVis(id,v){await api('/api/admin/games/'+id+'/visibility',{method:'POST',body:JSON.stringify({visible:!!v})});await loadGames();await loadAdmin()}async function uploadGame(id,file){if(!file)return;const f=new FormData();f.append('file',file);await api('/api/admin/games/'+id+'/upload',{method:'POST',body:f});await loadGames();await loadAdmin()}async function delGame(id){if(!confirm('确定删除这个游戏？'))return;await api('/api/admin/games/'+id,{method:'DELETE'});await loadGames();await loadAdmin()}
let hb;function startHeartbeat(){clearInterval(hb);const beat=()=>{if(document.visibilityState==='visible')api('/api/heartbeat',{method:'POST',body:JSON.stringify({game_id:Number(sessionStorage.getItem('alu_game'))||null})}).catch(()=>{})};beat();hb=setInterval(beat,30000);document.addEventListener('visibilitychange',beat)}
boot();</script></body></html>`;
}

export default {
  async fetch(request, env) {
    try {
      await ensureSchema(env);
      const url = new URL(request.url);
      if (url.pathname.startsWith('/socket.io/')) return proxyRobot(request, env, url.pathname);
      if (url.pathname.startsWith('/play/robot-battle')) return proxyRobot(request, env, url.pathname);
      if (url.pathname.startsWith('/api/')) return api(request, env, url);
      if (url.pathname.startsWith('/games/')) {
        const me = await auth(request, env); if (!me) return Response.redirect(new URL('/', url), 302);
        const m=url.pathname.match(/^\/games\/(\d+)/); if(!m) return html('<h1>Not found</h1>',404);
        const game=await env.DB.prepare('SELECT * FROM games WHERE id=?').bind(Number(m[1])).first(); if(!game || (!game.visible && me.role!=='admin')) return html('<h1>游戏不可用</h1>',404);
        return serveUploadedGame(game,env);
      }
      const dl=url.pathname.match(/^\/admin\/download\/(\d+)$/);
      if(dl){const me=await auth(request,env);if(!me||me.role!=='admin')return html('Forbidden',403);const g=await env.DB.prepare('SELECT * FROM games WHERE id=?').bind(Number(dl[1])).first();if(!g?.object_key)return html('Not found',404);const o=await env.GAMES.get(g.object_key);if(!o)return html('Not found',404);return new Response(o.body,{headers:{'content-type':'text/html; charset=utf-8','content-disposition':`attachment; filename="${g.slug||'game'}.html"`}})}
      if (url.pathname === '/' || url.pathname === '/index.html') return html(page());
      return html('<h1>404</h1>',404);
    } catch (e) { return json({ok:false,message:e.message||String(e)},500); }
  }
};
