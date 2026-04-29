const express      = require('express');
const cookieParser = require('cookie-parser');
const bcrypt       = require('bcryptjs');
const jwt          = require('jsonwebtoken');
const { v4: uuid } = require('uuid');
const path         = require('path');
const fs           = require('fs');

const app     = express();
const PORT    = process.env.PORT || 3000;
const SECRET  = process.env.JWT_SECRET || 'spyne_tracker_secret_change_in_prod';

app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// ── Database - JSON file based (persists on Render disk) ─────────────────────
const DATA_FILE = process.env.DATA_FILE || '/tmp/spyne_data.json';

function loadData() {
  try {
    if (fs.existsSync(DATA_FILE)) {
      return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
    }
  } catch(e) { console.log('Load error:', e.message); }
  return { users: [], items: [], logs: [] };
}

function saveData(data) {
  try {
    fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2));
  } catch(e) { console.log('Save error:', e.message); }
}

let DB = loadData();

// ── DB helpers ────────────────────────────────────────────────────────────────
const dbUsers = {
  all: ()         => DB.users,
  get: (id)       => DB.users.find(u => u.id === id),
  getByEmail: (e) => DB.users.find(u => u.email.toLowerCase() === e.toLowerCase()),
  add: (u)        => { DB.users.push(u); saveData(DB); },
  update: (id, fields) => {
    const idx = DB.users.findIndex(u => u.id === id);
    if (idx >= 0) { DB.users[idx] = { ...DB.users[idx], ...fields }; saveData(DB); }
  },
  delete: (id) => { DB.users = DB.users.filter(u => u.id !== id); saveData(DB); }
};

const dbItems = {
  all: ()    => DB.items,
  get: (id)  => DB.items.find(i => i.id === id),
  add: (item) => { DB.items.unshift(item); saveData(DB); },
  update: (id, fields) => {
    const idx = DB.items.findIndex(i => i.id === id);
    if (idx >= 0) { DB.items[idx] = { ...DB.items[idx], ...fields, updated_at: new Date().toISOString() }; saveData(DB); }
  },
  delete: (id) => { DB.items = DB.items.filter(i => i.id !== id); saveData(DB); }
};

const dbLogs = {
  forItem: (id) => DB.logs.filter(l => l.item_id === id).slice(0, 10),
  add: (log)    => { DB.logs.unshift(log); if (DB.logs.length > 500) DB.logs = DB.logs.slice(0, 500); saveData(DB); }
};

function enrichItems(items) {
  return items.map(item => ({
    ...item,
    writer:   dbUsers.get(item.content_writer_id)  || null,
    designer: dbUsers.get(item.design_assignee_id) || null,
    creator:  dbUsers.get(item.created_by)         || null,
  }));
}

// ── Auth middleware ───────────────────────────────────────────────────────────
function auth(req, res, next) {
  const authHeader = req.headers.authorization || '';
  const cookieToken = req.cookies ? req.cookies.token : '';
  const token = authHeader.replace('Bearer ', '') || cookieToken || '';
  if (!token) return res.status(401).json({ error: 'Not authenticated' });
  try { req.user = jwt.verify(token, SECRET); next(); }
  catch(e) { res.status(401).json({ error: 'Invalid token' }); }
}
function adminOnly(req, res, next) {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  next();
}

async function seedAdmin() {
  if (DB.users.length === 0) {
    const hash = await bcrypt.hash('spyne2024', 10);
    dbUsers.add({
      id: uuid(), name: 'Admin', email: 'admin@spyne.ai',
      password: hash, role: 'admin', avatar_color: '#D94F04',
      created_at: new Date().toISOString()
    });
    console.log('🔑 Default admin: admin@spyne.ai / spyne2024');
  }
}

// ── Auth routes ───────────────────────────────────────────────────────────────
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  const user = dbUsers.getByEmail(email);
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });
  const ok = await bcrypt.compare(password, user.password);
  if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
  const token = jwt.sign({ id: user.id, email: user.email, name: user.name, role: user.role }, SECRET, { expiresIn: '7d' });
  try { res.cookie('token', token, { httpOnly: true, maxAge: 7*86400*1000, sameSite: 'none', secure: true }); } catch(e) {}
  res.json({ token, user: { id: user.id, name: user.name, email: user.email, role: user.role, avatar_color: user.avatar_color } });
});

app.post('/api/auth/logout', (req, res) => { res.clearCookie('token'); res.json({ ok: true }); });

app.get('/api/auth/me', auth, (req, res) => {
  const user = dbUsers.get(req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({ id: user.id, name: user.name, email: user.email, role: user.role, avatar_color: user.avatar_color });
});

// ── User routes ───────────────────────────────────────────────────────────────
app.get('/api/users', auth, (req, res) => {
  res.json(dbUsers.all().map(u => ({ id: u.id, name: u.name, email: u.email, role: u.role, avatar_color: u.avatar_color, created_at: u.created_at })));
});

app.post('/api/users', auth, adminOnly, async (req, res) => {
  const { name, email, password, role, avatar_color } = req.body;
  if (!name || !email || !password || !role) return res.status(400).json({ error: 'Missing fields' });
  if (dbUsers.getByEmail(email)) return res.status(409).json({ error: 'Email already in use' });
  const id = uuid();
  dbUsers.add({ id, name, email, password: await bcrypt.hash(password, 10), role, avatar_color: avatar_color || '#D94F04', created_at: new Date().toISOString() });
  res.json({ ok: true, id });
});

app.put('/api/users/:id', auth, async (req, res) => {
  const isOwn = req.user.id === req.params.id;
  const isAdmin = req.user.role === 'admin';
  if (!isOwn && !isAdmin) return res.status(403).json({ error: 'Forbidden' });
  const user = dbUsers.get(req.params.id);
  if (!user) return res.status(404).json({ error: 'Not found' });
  const { name, avatar_color, password, role } = req.body;
  const updates = {
    name: name || user.name,
    avatar_color: avatar_color || user.avatar_color,
    role: (isAdmin && role) ? role : user.role,
    password: password ? await bcrypt.hash(password, 10) : user.password,
  };
  dbUsers.update(req.params.id, updates);
  res.json({ ok: true });
});

app.delete('/api/users/:id', auth, adminOnly, (req, res) => {
  if (req.params.id === req.user.id) return res.status(400).json({ error: 'Cannot delete yourself' });
  dbUsers.delete(req.params.id);
  res.json({ ok: true });
});

// ── Content item routes ───────────────────────────────────────────────────────
app.get('/api/items', auth, (req, res) => {
  let items = dbItems.all();
  if (req.user.role === 'design') items = items.filter(i => i.design_assignee_id === req.user.id);
  res.json(enrichItems(items));
});

app.post('/api/items', auth, (req, res) => {
  if (!['admin','content'].includes(req.user.role)) return res.status(403).json({ error: 'Forbidden' });
  const { keywords, type, category, cluster, ams, content_status, content_writer_id,
    content_delivery_date, seo_assigned_date, design_status, design_assignee_id,
    design_assign_date, design_delivery_date, overall_status, approved,
    live_url, new_content_link, notes, doc_link, images_needed, creative_drive } = req.body;
  if (!keywords) return res.status(400).json({ error: 'keywords required' });
  const id = uuid();
  const item = {
    id, keywords, type: type||'', category: category||'', cluster: cluster||'', ams: ams||'',
    content_status: content_status||'Not Started', content_writer_id: content_writer_id||'',
    content_delivery_date: content_delivery_date||'', seo_assigned_date: seo_assigned_date||'',
    design_status: design_status||'Not Assigned', design_assignee_id: design_assignee_id||'',
    design_assign_date: design_assign_date||'', design_delivery_date: design_delivery_date||'',
    overall_status: overall_status||'In Progress', approved: approved||'',
    live_url: live_url||'', new_content_link: new_content_link||'', notes: notes||'',
    doc_link: doc_link||'', images_needed: images_needed||'', creative_drive: creative_drive||'',
    created_by: req.user.id, created_at: new Date().toISOString(), updated_at: new Date().toISOString()
  };
  dbItems.add(item);
  dbLogs.add({ id: uuid(), item_id: id, user_id: req.user.id, user_name: req.user.name, action: 'created', details: `Created "${keywords}"`, created_at: new Date().toISOString() });
  res.json(enrichItems([item])[0]);
});

app.put('/api/items/:id', auth, (req, res) => {
  const item = dbItems.get(req.params.id);
  if (!item) return res.status(404).json({ error: 'Not found' });
  let updates = req.user.role === 'design'
    ? { design_status: req.body.design_status, design_delivery_date: req.body.design_delivery_date, notes: req.body.notes, creative_drive: req.body.creative_drive }
    : req.body;
  if (req.user.role === 'design' && req.body.design_status === 'Design Done') updates.overall_status = 'Content Done';
  // Remove undefined
  Object.keys(updates).forEach(k => updates[k] === undefined && delete updates[k]);
  dbItems.update(req.params.id, updates);
  dbLogs.add({ id: uuid(), item_id: req.params.id, user_id: req.user.id, user_name: req.user.name, action: 'updated', details: JSON.stringify(updates), created_at: new Date().toISOString() });
  res.json(enrichItems([dbItems.get(req.params.id)])[0]);
});

app.delete('/api/items/:id', auth, adminOnly, (req, res) => {
  dbItems.delete(req.params.id);
  res.json({ ok: true });
});

app.get('/api/items/:id/activity', auth, (req, res) => {
  res.json(dbLogs.forItem(req.params.id));
});

app.get('/api/stats', auth, (req, res) => {
  const items = dbItems.all();
  const byType = {};
  const byWriter = {};
  items.forEach(i => {
    if (i.type) byType[i.type] = (byType[i.type]||0) + 1;
    if (i.content_writer_id) {
      const w = dbUsers.get(i.content_writer_id);
      if (w) byWriter[w.name] = (byWriter[w.name]||0) + 1;
    }
  });
  res.json({
    total:      items.length,
    published:  items.filter(i => i.overall_status === 'Published').length,
    designDone: items.filter(i => i.design_status === 'Design Done').length,
    inProgress: items.filter(i => i.overall_status === 'In Progress').length,
    byType:     Object.entries(byType).map(([type,count]) => ({type,count})).sort((a,b) => b.count-a.count),
    byWriter:   Object.entries(byWriter).map(([name,count]) => ({name,count})).sort((a,b) => b.count-a.count).slice(0,8),
  });
});

app.get('/api/health', (req, res) => res.json({ ok: true, users: DB.users.length, items: DB.items.length }));

app.use((req, res) => {
  if (req.path.startsWith('/api/')) return res.status(404).json({ error: 'Not found' });
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ── Boot ──────────────────────────────────────────────────────────────────────
seedAdmin().then(() => {
  app.listen(PORT, () => {
    console.log(`🚀 Spyne Tracker on http://localhost:${PORT}`);
    console.log(`📦 Data file: ${DATA_FILE}`);
    console.log(`👥 Users: ${DB.users.length}, 📋 Items: ${DB.items.length}`);
  });
});
