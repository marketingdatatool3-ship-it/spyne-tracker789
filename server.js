const express      = require('express');
const cookieParser = require('cookie-parser');
const bcrypt       = require('bcryptjs');
const jwt          = require('jsonwebtoken');
const { v4: uuid } = require('uuid');
const path         = require('path');
const initSqlJs    = require('sql.js');
const fs           = require('fs');

const app     = express();
const PORT    = process.env.PORT || 3000;
const SECRET  = process.env.JWT_SECRET || 'spyne_tracker_secret_change_in_prod';
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'tracker.sqlite');

app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// ── Database ──────────────────────────────────────────────────────────────────
let db = null;

function save() {
  const data = db.export();
  fs.writeFileSync(DB_PATH, Buffer.from(data));
}
function all(sql, params = []) {
  const stmt = db.prepare(sql);
  stmt.bind(params);
  const rows = [];
  while (stmt.step()) rows.push(stmt.getAsObject());
  stmt.free();
  return rows;
}
function get(sql, params = []) { return all(sql, params)[0] || null; }
function run(sql, params = []) { db.run(sql, params); save(); }

async function initDB() {
  const SQL = await initSqlJs();
  if (fs.existsSync(DB_PATH)) {
    db = new SQL.Database(fs.readFileSync(DB_PATH));
  } else {
    db = new SQL.Database();
  }
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY, name TEXT NOT NULL, email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'content',
    avatar_color TEXT DEFAULT '#D94F04', created_at TEXT DEFAULT (datetime('now'))
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS content_items (
    id TEXT PRIMARY KEY, keywords TEXT NOT NULL, type TEXT, category TEXT,
    cluster TEXT, ams TEXT, content_status TEXT DEFAULT 'Not Started',
    content_writer_id TEXT, content_delivery_date TEXT, seo_assigned_date TEXT,
    design_status TEXT DEFAULT 'Not Assigned', design_assignee_id TEXT,
    design_assign_date TEXT, design_delivery_date TEXT,
    overall_status TEXT DEFAULT 'In Progress', approved TEXT,
    live_url TEXT, new_content_link TEXT, notes TEXT, created_by TEXT,
    created_at TEXT DEFAULT (datetime('now')), updated_at TEXT DEFAULT (datetime('now'))
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS activity_log (
    id TEXT PRIMARY KEY, item_id TEXT, user_id TEXT,
    action TEXT, details TEXT, created_at TEXT DEFAULT (datetime('now'))
  )`);
  save();
  console.log('✅ Database ready');
}

// ── Auth middleware ───────────────────────────────────────────────────────────
function auth(req, res, next) {
  const authHeader = req.headers.authorization || '';
  const cookieToken = req.cookies ? req.cookies.token : '';
  const token = authHeader.replace('Bearer ', '') || cookieToken || '';
  console.log('Auth attempt, token present:', !!token, 'length:', token.length);
  if (!token) return res.status(401).json({ error: 'Not authenticated' });
  try { req.user = jwt.verify(token, SECRET); next(); }
  catch(e) { 
    console.log('Token verify failed:', e.message);
    res.status(401).json({ error: 'Invalid token' }); 
  }
}
function adminOnly(req, res, next) {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  next();
}

async function seedAdmin() {
  const existing = get('SELECT id FROM users LIMIT 1');
  if (!existing) {
    const hash = await bcrypt.hash('spyne2024', 10);
    run('INSERT INTO users (id,name,email,password,role,avatar_color) VALUES (?,?,?,?,?,?)',
      [uuid(), 'Admin', 'admin@spyne.ai', hash, 'admin', '#D94F04']);
    console.log('🔑 Default admin: admin@spyne.ai / spyne2024');
  }
}

// ── Auth routes ───────────────────────────────────────────────────────────────
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  const user = get('SELECT * FROM users WHERE LOWER(email)=LOWER(?)', [email]);
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });
  const ok = await bcrypt.compare(password, user.password);
  if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
  const token = jwt.sign({ id: user.id, email: user.email, name: user.name, role: user.role }, SECRET, { expiresIn: '7d' });
  // Set cookie as backup
  try { res.cookie('token', token, { httpOnly: true, maxAge: 7 * 86400 * 1000, sameSite: 'none', secure: true }); } catch(e) {}
  // Always return token in body - frontend uses this
  res.json({ token, user: { id: user.id, name: user.name, email: user.email, role: user.role, avatar_color: user.avatar_color } });
});
app.post('/api/auth/logout', (req, res) => { res.clearCookie('token'); res.json({ ok: true }); });
app.get('/api/auth/me', auth, (req, res) => {
  res.json(get('SELECT id,name,email,role,avatar_color FROM users WHERE id=?', [req.user.id]));
});

// ── User routes ───────────────────────────────────────────────────────────────
app.get('/api/users', auth, (req, res) => {
  res.json(all('SELECT id,name,email,role,avatar_color,created_at FROM users ORDER BY name'));
});
app.post('/api/users', auth, adminOnly, async (req, res) => {
  const { name, email, password, role, avatar_color } = req.body;
  if (!name || !email || !password || !role) return res.status(400).json({ error: 'Missing fields' });
  if (get('SELECT id FROM users WHERE LOWER(email)=LOWER(?)', [email])) return res.status(409).json({ error: 'Email in use' });
  const id = uuid();
  run('INSERT INTO users (id,name,email,password,role,avatar_color) VALUES (?,?,?,?,?,?)',
    [id, name, email, await bcrypt.hash(password, 10), role, avatar_color || '#D94F04']);
  res.json({ ok: true, id });
});
app.put('/api/users/:id', auth, async (req, res) => {
  const isOwn = req.user.id === req.params.id;
  const isAdmin = req.user.role === 'admin';
  if (!isOwn && !isAdmin) return res.status(403).json({ error: 'Forbidden' });
  const user = get('SELECT * FROM users WHERE id=?', [req.params.id]);
  if (!user) return res.status(404).json({ error: 'Not found' });
  const { name, avatar_color, password, role } = req.body;
  run('UPDATE users SET name=?,avatar_color=?,role=?,password=? WHERE id=?', [
    name || user.name, avatar_color || user.avatar_color,
    (isAdmin && role) ? role : user.role,
    password ? await bcrypt.hash(password, 10) : user.password,
    req.params.id
  ]);
  res.json({ ok: true });
});
app.delete('/api/users/:id', auth, adminOnly, (req, res) => {
  if (req.params.id === req.user.id) return res.status(400).json({ error: 'Cannot delete yourself' });
  run('DELETE FROM users WHERE id=?', [req.params.id]);
  res.json({ ok: true });
});

// ── Content item routes ───────────────────────────────────────────────────────
function enrichItems(items) {
  const users = all('SELECT id,name,avatar_color,role FROM users');
  const map = {};
  users.forEach(u => { map[u.id] = u; });
  return items.map(item => ({
    ...item,
    writer:   map[item.content_writer_id]  || null,
    designer: map[item.design_assignee_id] || null,
    creator:  map[item.created_by]         || null,
  }));
}
app.get('/api/items', auth, (req, res) => {
  let sql = 'SELECT * FROM content_items WHERE 1=1';
  const params = [];
  if (req.user.role === 'design') { sql += ' AND design_assignee_id=?'; params.push(req.user.id); }
  sql += ' ORDER BY created_at DESC';
  res.json(enrichItems(all(sql, params)));
});
app.post('/api/items', auth, (req, res) => {
  if (!['admin','content'].includes(req.user.role)) return res.status(403).json({ error: 'Forbidden' });
  const { keywords, type, category, cluster, ams, content_status, content_writer_id,
    content_delivery_date, seo_assigned_date, design_status, design_assignee_id,
    design_assign_date, design_delivery_date, overall_status, approved,
    live_url, new_content_link, notes } = req.body;
  if (!keywords) return res.status(400).json({ error: 'keywords required' });
  const id = uuid();
  run(`INSERT INTO content_items (id,keywords,type,category,cluster,ams,content_status,
    content_writer_id,content_delivery_date,seo_assigned_date,design_status,design_assignee_id,
    design_assign_date,design_delivery_date,overall_status,approved,live_url,new_content_link,
    notes,created_by) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
    [id,keywords,type,category,cluster,ams,content_status||'Not Started',
     content_writer_id||null,content_delivery_date||null,seo_assigned_date||null,
     design_status||'Not Assigned',design_assignee_id||null,design_assign_date||null,
     design_delivery_date||null,overall_status||'In Progress',approved||null,
     live_url||null,new_content_link||null,notes||null,req.user.id]);
  run('INSERT INTO activity_log (id,item_id,user_id,action,details) VALUES (?,?,?,?,?)',
    [uuid(), id, req.user.id, 'created', `Created "${keywords}"`]);
  res.json(enrichItems([get('SELECT * FROM content_items WHERE id=?', [id])])[0]);
});
app.put('/api/items/:id', auth, (req, res) => {
  const item = get('SELECT * FROM content_items WHERE id=?', [req.params.id]);
  if (!item) return res.status(404).json({ error: 'Not found' });
  let allowed = req.user.role === 'design'
    ? { design_status: req.body.design_status, design_delivery_date: req.body.design_delivery_date, notes: req.body.notes }
    : req.body;
  if (req.user.role === 'design' && req.body.design_status === 'Design Done') allowed.overall_status = 'Content Done';
  const fields = ['keywords','type','category','cluster','ams','content_status','content_writer_id',
    'content_delivery_date','seo_assigned_date','design_status','design_assignee_id',
    'design_assign_date','design_delivery_date','overall_status','approved','live_url','new_content_link','notes'];
  const sets = []; const params = [];
  fields.forEach(f => { if (allowed[f] !== undefined) { sets.push(`${f}=?`); params.push(allowed[f]); } });
  if (!sets.length) return res.status(400).json({ error: 'Nothing to update' });
  sets.push("updated_at=datetime('now')");
  params.push(req.params.id);
  run(`UPDATE content_items SET ${sets.join(',')} WHERE id=?`, params);
  run('INSERT INTO activity_log (id,item_id,user_id,action,details) VALUES (?,?,?,?,?)',
    [uuid(), req.params.id, req.user.id, 'updated', JSON.stringify(allowed)]);
  res.json(enrichItems([get('SELECT * FROM content_items WHERE id=?', [req.params.id])])[0]);
});
app.delete('/api/items/:id', auth, adminOnly, (req, res) => {
  run('DELETE FROM content_items WHERE id=?', [req.params.id]);
  res.json({ ok: true });
});
app.get('/api/items/:id/activity', auth, (req, res) => {
  res.json(all(`SELECT a.*,u.name as user_name,u.avatar_color FROM activity_log a
    LEFT JOIN users u ON a.user_id=u.id WHERE a.item_id=? ORDER BY a.created_at DESC`, [req.params.id]));
});
app.get('/api/stats', auth, (req, res) => {
  res.json({
    total:      get('SELECT COUNT(*) as n FROM content_items')?.n || 0,
    published:  get("SELECT COUNT(*) as n FROM content_items WHERE overall_status='Published'")?.n || 0,
    designDone: get("SELECT COUNT(*) as n FROM content_items WHERE design_status='Design Done'")?.n || 0,
    inProgress: get("SELECT COUNT(*) as n FROM content_items WHERE overall_status='In Progress'")?.n || 0,
    byType:     all("SELECT type,COUNT(*) as count FROM content_items WHERE type IS NOT NULL GROUP BY type ORDER BY count DESC"),
    byWriter:   all(`SELECT u.name,COUNT(*) as count FROM content_items ci JOIN users u ON ci.content_writer_id=u.id GROUP BY u.id ORDER BY count DESC LIMIT 8`),
  });
});
app.get('/api/health', (req, res) => res.json({ ok: true }));
app.use((req, res, next) => {
  if (req.path.startsWith('/api/')) return res.status(404).json({ error: 'Not found' });
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ── Boot ──────────────────────────────────────────────────────────────────────
initDB().then(async () => {
  await seedAdmin();
  app.listen(PORT, () => console.log(`🚀 Spyne Tracker on http://localhost:${PORT}`));
});
