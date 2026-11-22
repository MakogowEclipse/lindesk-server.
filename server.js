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
  alter table messages add column if not exists channel_id int;`);
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
  res.json({ token: sign(u), user: { id: u.id, username: u.username } });
});

const uids = c => c.name.split(':').slice(1).map(Number);
async function access(uid, cid) {
  const c = (await q('select * from channels where id=$1', [cid])).rows[0]; if (!c) return null;
  if (c.type === 'dm') return uids(c).includes(uid) ? c : null;
  return (await q('select 1 from members where group_id=$1 and user_id=$2', [c.group_id, uid])).rowCount ? c : null;
}
const ping = (...ids) => ids.forEach(i => io.to('u' + i).emit('friends:update'));
const areFriends = async (a, b) => (await q(`select 1 from friendships where status='ok' and ((a=$1 and b=$2) or (a=$2 and b=$1))`, [a, b])).rowCount > 0;

// ---- Grupos e canais ----
app.get('/groups', auth, async (req, res) => {
  res.json((await q(`select g.id,g.name,g.code,g.owner_id from chat_groups g join members m on m.group_id=g.id where m.user_id=$1 order by g.id`, [req.user.id])).rows);
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
  const m = await q('select 1 from members where group_id=$1 and user_id=$2', [req.params.id, req.user.id]);
  if (!m.rowCount) return res.status(403).json({ error: 'Sem acesso' });
  let r = await q('select id,name,type from channels where group_id=$1 order by id', [req.params.id]);
  if (!r.rowCount) { await q(`insert into channels(group_id,name,type) values($1,'geral','text'),($1,'Sala de voz','voice')`, [req.params.id]); r = await q('select id,name,type from channels where group_id=$1 order by id', [req.params.id]); }
  res.json(r.rows);
});
app.post('/groups/:id/channels', auth, async (req, res) => {
  const g = (await q('select owner_id from chat_groups where id=$1', [req.params.id])).rows[0];
  if (!g || g.owner_id !== req.user.id) return res.status(403).json({ error: 'Só o dono do grupo cria canais' });
  const type = req.body.type === 'voice' ? 'voice' : 'text';
  res.json((await q('insert into channels(group_id,name,type) values($1,$2,$3) returning id,name,type', [req.params.id, req.body.name, type])).rows[0]);
});
app.get('/channels/:id/messages', auth, async (req, res) => {
  if (!(await access(req.user.id, req.params.id))) return res.status(403).json({ error: 'Sem acesso' });
  res.json((await q('select username,text,created_at from messages where channel_id=$1 order by id desc limit 50', [req.params.id])).rows.reverse());
});

// ---- Amigos e mensagens diretas ----
app.get('/friends', auth, async (req, res) => {
  const id = req.user.id;
  const r = (await q(`select f.a,f.b,f.status,u.id uid,u.username from friendships f join users u on u.id=(case when f.a=$1 then f.b else f.a end) where f.a=$1 or f.b=$1`, [id])).rows;
  const pick = fn => r.filter(fn).map(x => ({ id: x.uid, username: x.username }));
  res.json({ friends: pick(x => x.status === 'ok'), incoming: pick(x => x.status === 'pending' && x.b === id), outgoing: pick(x => x.status === 'pending' && x.a === id) });
});
app.post('/friends/request', auth, async (req, res) => {
  const u = (await q('select id from users where lower(username)=lower($1)', [req.body.username || ''])).rows[0];
  if (!u || u.id === req.user.id) return res.status(404).json({ error: 'Usuário não encontrado' });
  const rev = await q(`update friendships set status='ok' where a=$1 and b=$2`, [u.id, req.user.id]);
  if (!rev.rowCount) await q(`insert into friendships values($1,$2,'pending') on conflict do nothing`, [req.user.id, u.id]);
  ping(req.user.id, u.id); res.json({ ok: true });
});
app.post('/friends/accept', auth, async (req, res) => {
  await q(`update friendships set status='ok' where a=$1 and b=$2`, [req.body.id, req.user.id]); ping(req.user.id, req.body.id); res.json({ ok: true });
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

// ---- Tempo real: chat + sinalização WebRTC ----
io.use((s, next) => {
  try { s.user = jwt.verify(s.handshake.auth.token, SECRET); next(); } catch { next(new Error('auth')); }
});
io.on('connection', socket => {
  const uid = socket.user.id; socket.join('u' + uid);
  socket.on('chat:join', async cid => { if (await access(uid, cid)) socket.join('c' + cid); });
  socket.on('chat:send', async ({ cid, text }) => {
    if (!text || !(await access(uid, cid))) return;
    await q('insert into messages(channel_id,username,text) values($1,$2,$3)', [cid, socket.user.username, text]);
    io.to('c' + cid).emit('chat:msg', { cid, username: socket.user.username, text, created_at: new Date() });
  });
  socket.on('voice:join', async cid => {
    const c = await access(uid, cid); if (!c) return;
    const room = 'v' + cid;
    const others = [...(io.sockets.adapter.rooms.get(room) || [])].map(id => ({ id, username: io.sockets.sockets.get(id).user.username }));
    socket.voiceRoom = room; socket.join(room); socket.emit('voice:peers', others);
    if (c.type === 'dm' && !others.length) { const o = uids(c).find(x => x !== uid); io.to('u' + o).emit('call:ring', { username: socket.user.username, cid }); }
  });
  socket.on('voice:signal', ({ to, data }) => io.to(to).emit('voice:signal', { from: socket.id, username: socket.user.username, data }));
  const leave = () => { if (socket.voiceRoom) { socket.to(socket.voiceRoom).emit('voice:left', socket.id); socket.leave(socket.voiceRoom); socket.voiceRoom = null; } };
  socket.on('voice:leave', leave); socket.on('disconnect', leave);
});

init().then(() => server.listen(process.env.PORT || 3000, () => console.log('Lindesk server rodando')));
