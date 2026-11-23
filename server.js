require('dotenv').config();
const express = require('express'), http = require('http'), cors = require('cors');
const { Pool } = require('pg'), bcrypt = require('bcryptjs'), jwt = require('jsonwebtoken');
const { Server } = require('socket.io');

const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });
const SECRET = process.env.JWT_SECRET;
const q = (t, p) => pool.query(t, p);
const app = express(); app.use(cors()); app.use(express.json());
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' } });

async function init() {
  await q(`create table if not exists users(id serial primary key, username text unique not null,
    email text unique not null, password_hash text not null, created_at timestamptz default now());
  create table if not exists chat_groups(id serial primary key, name text not null, code text unique not null, owner_id int);
  create table if not exists members(group_id int, user_id int, primary key(group_id, user_id));
  create table if not exists messages(id serial primary key, group_id int, username text, text text, created_at timestamptz default now());
  create table if not exists friendships(a int, b int, status text, primary key(a,b));
  create table if not exists channels(id serial primary key, group_id int, name text, type text);
  alter table messages add column if not exists channel_id int;
  alter table users add column if not exists avatar text;
  alter table users add column if not exists status text default 'online';
  alter table chat_groups add column if not exists avatar text;
  alter table members add column if not exists role text default 'member';
  alter table channels add column if not exists perm_view text default 'all';
  alter table channels add column if not exists perm_write text default 'all';`);
}
const sign = u => jwt.sign({ id: u.id, username: u.username }, SECRET, { expiresIn: '30d' });
const auth = (req, res, next) => {
  try { req.user = jwt.verify((req.headers.authorization || '').replace('Bearer ', ''), SECRET); next(); }
  catch { res.status(401).json({ error: 'Não autenticado' }); }
};

app.get('/', (_, res) => res.send('Lindesk server online'));

app.post('/register', async (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !email || !password || password.length < 6)
    return res.status(400).json({ error: 'Preencha tudo (senha com 6+ caracteres)' });
  try {
    const hash = await bcrypt.hash(password, 10);
    const r = await q('insert into users(username,email,password_hash) values($1,$2,$3) returning id,username',
      [username.trim(), email.trim().toLowerCase(), hash]);
    res.json({ token: sign(r.rows[0]), user: r.rows[0] });
  } catch (e) {
    res.status(409).json({ error: 'Usuário ou e-mail já existe' });
  }
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const r = await q('select * from users where email=$1', [(email || '').trim().toLowerCase()]);
  const u = r.rows[0];
  if (!u || !(await bcrypt.compare(password || '', u.password_hash)))
    return res.status(401).json({ error: 'E-mail ou senha incorretos' });
  res.json({ token: sign(u), user: { id: u.id, username: u.username, avatar: u.avatar, status: u.status } });
});

const uids = c => c.name.split(':').slice(1).map(Number);
const roleOf = async (uid, gid) => {
  const g = (await q('select owner_id from chat_groups where id=$1', [gid])).rows[0]; if (!g) return null;
  if (g.owner_id === uid) return 'owner';
  const m = (await q('select role from members where group_id=$1 and user_id=$2', [gid, uid])).rows[0]; return m ? (m.role || 'member') : null;
};
const isAdm = r => r === 'owner' || r === 'admin';
async function access(uid, cid) {
  const c = (await q('select * from channels where id=$1', [cid])).rows[0]; if (!c) return null;
  if (c.type === 'dm') return uids(c).includes(uid) ? c : null;
  const r = await roleOf(uid, c.group_id); if (!r) return null;
  c.admin = isAdm(r); return c.perm_view === 'admin' && !c.admin ? null : c;
}
const ping = (...ids) => ids.forEach(i => io.to('u' + i).emit('friends:update'));
const areFriends = async (a, b) => (await q(`select 1 from friendships where status='ok' and ((a=$1 and b=$2) or (a=$2 and b=$1))`, [a, b])).rowCount > 0;

// ---- Grupos e canais ----
app.get('/groups', auth, async (req, res) => {
  res.json((await q(`select g.id,g.name,g.code,g.owner_id,g.avatar,m.role from chat_groups g join members m on m.group_id=g.id where m.user_id=$1 order by g.id`, [req.user.id])).rows);
});
app.post('/groups', auth, async (req, res) => {
  const code = Math.random().toString(36).slice(2, 8).toUpperCase();
  const g = (await q('insert into chat_groups(name,code,owner_id) values($1,$2,$3) returning *', [req.body.name, code, req.user.id])).rows[0];
  await q('insert into members values($1,$2)', [g.id, req.user.id]);
  await q(`insert into channels(group_id,name,type) values($1,'geral','text'),($1,'Sala de voz','voice')`, [g.id]);
  res.json(g);
});
app.post('/groups/join', auth, async (req, res) => {
  const g = (await q('select * from chat_groups where code=$1', [(req.body.code || '').toUpperCase()])).rows[0];
  if (!g) return res.status(404).json({ error: 'Código inválido' });
  await q('insert into members values($1,$2) on conflict do nothing', [g.id, req.user.id]);
  res.json(g);
});
app.get('/groups/:id/channels', auth, async (req, res) => {
  const role = await roleOf(req.user.id, req.params.id);
  if (!role) return res.status(403).json({ error: 'Sem acesso' });
  const sel = 'select id,name,type,perm_view,perm_write from channels where group_id=$1 order by id';
  let r = await q(sel, [req.params.id]);
  if (!r.rowCount) { await q(`insert into channels(group_id,name,type) values($1,'geral','text'),($1,'Sala de voz','voice')`, [req.params.id]); r = await q(sel, [req.params.id]); }
  res.json(r.rows.filter(c => c.perm_view !== 'admin' || isAdm(role)));
});
app.post('/groups/:id/channels', auth, async (req, res) => {
  if (!isAdm(await roleOf(req.user.id, req.params.id))) return res.status(403).json({ error: 'Só admins criam canais' });
  const type = req.body.type === 'voice' ? 'voice' : 'text';
  res.json((await q('insert into channels(group_id,name,type) values($1,$2,$3) returning id,name,type', [req.params.id, req.body.name, type])).rows[0]);
});
app.get('/channels/:id/messages', auth, async (req, res) => {
  if (!(await access(req.user.id, req.params.id))) return res.status(403).json({ error: 'Sem acesso' });
  res.json((await q('select m.username,m.text,m.created_at,u.avatar from messages m left join users u on u.username=m.username where m.channel_id=$1 order by m.id desc limit 50', [req.params.id])).rows.reverse());
});

// ---- Amigos e mensagens diretas ----
app.get('/friends', auth, async (req, res) => {
  const id = req.user.id;
  const r = (await q(`select f.a,f.b,f.status,u.id uid,u.username,u.avatar from friendships f join users u on u.id=(case when f.a=$1 then f.b else f.a end) where f.a=$1 or f.b=$1`, [id])).rows;
  const pick = fn => r.filter(fn).map(x => ({ id: x.uid, username: x.username, avatar: x.avatar, status: presenceOf(x.uid) }));
  res.json({ friends: pick(x => x.status === 'ok'), incoming: pick(x => x.status === 'pending' && x.b === id), outgoing: pick(x => x.status === 'pending' && x.a === id) });
});
app.post('/friends/request', auth, async (req, res) => {
  const u = (await q('select id from users where lower(username)=lower($1)', [req.body.username || ''])).rows[0];
  if (!u || u.id === req.user.id) return res.status(404).json({ error: 'Usuário não encontrado' });
  const rev = await q(`update friendships set status='ok' where a=$1 and b=$2`, [u.id, req.user.id]);
  if (!rev.rowCount) await q(`insert into friendships values($1,$2,'pending') on conflict do nothing`, [req.user.id, u.id]);
  ping(req.user.id, u.id); io.to('u' + u.id).emit('notify', { kind: rev.rowCount ? 'friendok' : 'friend', username: req.user.username }); res.json({ ok: true });
});
app.post('/friends/accept', auth, async (req, res) => {
  await q(`update friendships set status='ok' where a=$1 and b=$2`, [req.body.id, req.user.id]); ping(req.user.id, req.body.id); io.to('u' + req.body.id).emit('notify', { kind: 'friendok', username: req.user.username }); res.json({ ok: true });
});
app.post('/friends/remove', auth, async (req, res) => {
  await q('delete from friendships where (a=$1 and b=$2) or (a=$2 and b=$1)', [req.user.id, req.body.id]); ping(req.user.id, req.body.id); res.json({ ok: true });
});
app.get('/dm/:uid', auth, async (req, res) => {
  const o = +req.params.uid;
  if (!(await areFriends(req.user.id, o))) return res.status(403).json({ error: 'Vocês não são amigos' });
  const name = `dm:${Math.min(req.user.id, o)}:${Math.max(req.user.id, o)}`;
  let c = (await q('select id from channels where name=$1', [name])).rows[0];
  if (!c) c = (await q(`insert into channels(name,type) values($1,'dm') returning id`, [name])).rows[0];
  res.json({ id: c.id });
});

async function deleteGroup(gid) {
  await q('delete from messages where channel_id in (select id from channels where group_id=$1)', [gid]);
  await q('delete from channels where group_id=$1', [gid]); await q('delete from members where group_id=$1', [gid]); await q('delete from chat_groups where id=$1', [gid]);
  io.to('grp' + gid).emit('group:deleted', +gid);
}
const changed = gid => io.to('grp' + gid).emit('group:changed', +gid);
app.post('/groups/:id/leave', auth, async (req, res) => {
  const r = await roleOf(req.user.id, req.params.id);
  if (!r) return res.status(404).json({ error: 'Você não está neste grupo' });
  if (r === 'owner') return res.status(400).json({ error: 'O dono não pode sair do próprio grupo. Apague o grupo se quiser encerrá-lo.' });
  await q('delete from members where group_id=$1 and user_id=$2', [req.params.id, req.user.id]);
  io.in('u' + req.user.id).emit('group:left', +req.params.id); io.in('u' + req.user.id).socketsLeave('grp' + req.params.id);
  changed(req.params.id); res.json({ ok: true });
});
app.delete('/groups/:id', auth, async (req, res) => {
  if ((await roleOf(req.user.id, req.params.id)) !== 'owner') return res.status(403).json({ error: 'Só o dono apaga o grupo' });
  await deleteGroup(req.params.id); res.json({ ok: true });
});
app.post('/groups/:id/avatar', auth, async (req, res) => {
  if (!isAdm(await roleOf(req.user.id, req.params.id))) return res.status(403).json({ error: 'Só admins mudam a foto' });
  const a = req.body.avatar; if (!a || !a.startsWith('data:image/') || a.length > 200000) return res.status(400).json({ error: 'Imagem inválida ou muito grande' });
  await q('update chat_groups set avatar=$1 where id=$2', [a, req.params.id]); changed(req.params.id); res.json({ ok: true });
});
app.get('/groups/:id/members', auth, async (req, res) => {
  if (!(await roleOf(req.user.id, req.params.id))) return res.status(403).json({ error: 'Sem acesso' });
  res.json((await q('select u.id,u.username,u.avatar,m.role from members m join users u on u.id=m.user_id where m.group_id=$1 order by u.username', [req.params.id])).rows);
});
app.post('/groups/:id/members/:uid/role', auth, async (req, res) => {
  if ((await roleOf(req.user.id, req.params.id)) !== 'owner') return res.status(403).json({ error: 'Só o dono muda cargos' });
  await q('update members set role=$1 where group_id=$2 and user_id=$3', [req.body.role === 'admin' ? 'admin' : 'member', req.params.id, req.params.uid]); changed(req.params.id); res.json({ ok: true });
});
app.post('/channels/:id/perms', auth, async (req, res) => {
  const c = (await q('select * from channels where id=$1', [req.params.id])).rows[0];
  if (!c || c.type === 'dm' || !isAdm(await roleOf(req.user.id, c.group_id))) return res.status(403).json({ error: 'Sem permissão' });
  if (!['perm_view', 'perm_write'].includes(req.body.field)) return res.status(400).json({ error: 'Campo inválido' });
  await q(`update channels set ${req.body.field}=$1 where id=$2`, [req.body.value === 'admin' ? 'admin' : 'all', c.id]); changed(c.group_id); res.json({ ok: true });
});
app.delete('/me', auth, async (req, res) => {
  const u = (await q('select * from users where id=$1', [req.user.id])).rows[0];
  if (!u || !(await bcrypt.compare(req.body.password || '', u.password_hash))) return res.status(401).json({ error: 'Senha incorreta' });
  for (const g of (await q('select id from chat_groups where owner_id=$1', [u.id])).rows) await deleteGroup(g.id);
  const dm = `select id from channels where type='dm' and (name like $1 or name like $2)`, p = [`dm:${u.id}:%`, `dm:%:${u.id}`];
  await q(`delete from messages where channel_id in (${dm})`, p); await q(`delete from channels where id in (${dm})`, p);
  await q('delete from members where user_id=$1', [u.id]); await q('delete from friendships where a=$1 or b=$1', [u.id]);
  await q('delete from messages where username=$1', [u.username]); await q('delete from users where id=$1', [u.id]);
  io.in('u' + u.id).disconnectSockets(true); res.json({ ok: true });
});
// ---- Presença (online / não perturbe / offline) ----
const statusMap = new Map();
function presenceOf(uid) {
  const room = io.sockets.adapter.rooms.get('u' + uid), s = statusMap.get(uid) || 'online';
  return !room || !room.size || s === 'offline' ? 'offline' : s;
}
async function broadcast(uid) {
  const st = presenceOf(uid);
  const r = await q(`select case when a=$1 then b else a end fid from friendships where status='ok' and (a=$1 or b=$1)`, [uid]);
  [...r.rows.map(x => x.fid), uid].forEach(f => io.to('u' + f).emit('presence', { id: uid, status: st }));
}
app.get('/me', auth, async (req, res) => {
  const u = (await q('select id,username,avatar,status from users where id=$1', [req.user.id])).rows[0];
  if (!u) return res.status(401).json({ error: 'Não autenticado' }); res.json(u);
});
app.post('/me/status', auth, async (req, res) => {
  const s = ['online', 'dnd', 'offline'].includes(req.body.status) ? req.body.status : 'online';
  await q('update users set status=$1 where id=$2', [s, req.user.id]); statusMap.set(req.user.id, s); broadcast(req.user.id); res.json({ ok: true });
});
app.post('/me/avatar', auth, async (req, res) => {
  const a = req.body.avatar;
  if (!a || !a.startsWith('data:image/') || a.length > 200000) return res.status(400).json({ error: 'Imagem inválida ou muito grande' });
  await q('update users set avatar=$1 where id=$2', [a, req.user.id]); res.json({ ok: true });
});
async function voiceUsers(cid) {
  const n = [...(io.sockets.adapter.rooms.get('v' + cid) || [])].map(id => io.sockets.sockets.get(id).user.username);
  return n.length ? (await q('select username,avatar from users where username=any($1)', [n])).rows : [];
}
async function pushVoice(cid) {
  const c = (await q('select * from channels where id=$1', [cid])).rows[0];
  if (c && c.type !== 'dm') io.to('grp' + c.group_id).emit('voice:users', { cid: +cid, users: await voiceUsers(cid) });
}

// ---- Tempo real: chat + sinalização WebRTC ----
io.use((s, next) => {
  try { s.user = jwt.verify(s.handshake.auth.token, SECRET); next(); } catch { next(new Error('auth')); }
});
io.on('connection', socket => {
  const uid = socket.user.id; socket.join('u' + uid);
  q('select status from users where id=$1', [uid]).then(r => { statusMap.set(uid, (r.rows[0] && r.rows[0].status) || 'online'); broadcast(uid); });
  socket.on('disconnect', () => broadcast(uid));
  q('select group_id from members where user_id=$1', [uid]).then(r => r.rows.forEach(x => socket.join('grp' + x.group_id)));
  socket.on('chat:join', async cid => { if (await access(uid, cid)) socket.join('c' + cid); });
  socket.on('chat:send', async ({ cid, text }) => {
    const c = text && await access(uid, cid); if (!c) return;
    if (c.type === 'text' && c.perm_write === 'admin' && !c.admin) return socket.emit('chat:denied');
    await q('insert into messages(channel_id,username,text) values($1,$2,$3)', [cid, socket.user.username, text]);
    const av = (await q('select avatar from users where id=$1', [uid])).rows[0];
    io.to('c' + cid).emit('chat:msg', { cid, username: socket.user.username, text, created_at: new Date(), avatar: av && av.avatar });
    if (c.type === 'dm') { const o = uids(c).find(x => x !== uid); io.to('u' + o).emit('notify', { kind: 'dm', cid, username: socket.user.username, text: text.slice(0, 120) }); }
  });
  socket.on('voice:query', async gid => {
    if (!(await q('select 1 from members where group_id=$1 and user_id=$2', [gid, uid])).rowCount) return;
    socket.join('grp' + gid);
    for (const c of (await q(`select id from channels where group_id=$1 and type='voice'`, [gid])).rows) socket.emit('voice:users', { cid: c.id, users: await voiceUsers(c.id) });
  });
  socket.on('voice:join', async cid => {
    const c = await access(uid, cid); if (!c) return;
    const room = 'v' + cid;
    const others = [...(io.sockets.adapter.rooms.get(room) || [])].map(id => ({ id, username: io.sockets.sockets.get(id).user.username }));
    socket.voiceRoom = room; socket.voiceCid = cid; socket.join(room); socket.emit('voice:peers', others); pushVoice(cid); socket.to(room).emit('voice:joined', { username: socket.user.username });
    if (c.type === 'dm' && !others.length) { const o = uids(c).find(x => x !== uid); socket.ringTo = o; io.to('u' + o).emit('call:ring', { username: socket.user.username, cid }); }
  });
  socket.on('voice:signal', ({ to, data }) => io.to(to).emit('voice:signal', { from: socket.id, username: socket.user.username, data }));
  const leave = () => {
    if (!socket.voiceRoom) return;
    socket.to(socket.voiceRoom).emit('voice:left', socket.id); socket.leave(socket.voiceRoom);
    const cid = socket.voiceCid; socket.voiceRoom = null; pushVoice(cid);
    if (socket.ringTo) { io.to('u' + socket.ringTo).emit('call:cancel'); socket.ringTo = null; }
  };
  socket.on('voice:leave', leave); socket.on('disconnect', leave);
});

init().then(() => server.listen(process.env.PORT || 3000, () => console.log('Lindesk server rodando')));