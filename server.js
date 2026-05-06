const express      = require('express');
const cookieParser = require('cookie-parser');
const bcrypt       = require('bcryptjs');
const jwt          = require('jsonwebtoken');
const { v4: uuid } = require('uuid');
const path         = require('path');
const { Pool }     = require('pg');

const app    = express();
const PORT   = process.env.PORT || 3000;
const SECRET = process.env.JWT_SECRET || 'spyne_tracker_secret_change_in_prod';

app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

async function query(sql, params = []) {
  const client = await pool.connect();
  try { const res = await client.query(sql, params); return res.rows; }
  finally { client.release(); }
}
async function queryOne(sql, params = []) {
  const rows = await query(sql, params); return rows[0] || null;
}

async function initDB() {
  await query(`CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, name TEXT NOT NULL, email TEXT UNIQUE NOT NULL, password TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'content', avatar_color TEXT DEFAULT '#D94F04', created_at TIMESTAMPTZ DEFAULT NOW())`);
  await query(`CREATE TABLE IF NOT EXISTS content_items (id TEXT PRIMARY KEY, keywords TEXT NOT NULL, type TEXT DEFAULT '', category TEXT DEFAULT '', cluster TEXT DEFAULT '', ams TEXT DEFAULT '', content_status TEXT DEFAULT 'Not Started', content_writer_id TEXT DEFAULT '', content_delivery_date TEXT DEFAULT '', seo_assigned_date TEXT DEFAULT '', design_status TEXT DEFAULT 'Not Assigned', design_assignee_id TEXT DEFAULT '', design_assign_date TEXT DEFAULT '', design_delivery_date TEXT DEFAULT '', overall_status TEXT DEFAULT 'In Progress', approved TEXT DEFAULT '', live_url TEXT DEFAULT '', new_content_link TEXT DEFAULT '', notes TEXT DEFAULT '', doc_link TEXT DEFAULT '', images_needed TEXT DEFAULT '', creative_drive TEXT DEFAULT '', created_by TEXT DEFAULT '', created_at TIMESTAMPTZ DEFAULT NOW(), updated_at TIMESTAMPTZ DEFAULT NOW())`);
  await query(`CREATE TABLE IF NOT EXISTS activity_log (id TEXT PRIMARY KEY, item_id TEXT, user_id TEXT, user_name TEXT, action TEXT, details TEXT, created_at TIMESTAMPTZ DEFAULT NOW())`);
  try { await query("ALTER TABLE content_items ADD COLUMN IF NOT EXISTS doc_link TEXT DEFAULT ''"); } catch(e) {}
  try { await query("ALTER TABLE content_items ADD COLUMN IF NOT EXISTS images_needed TEXT DEFAULT ''"); } catch(e) {}
  try { await query("ALTER TABLE content_items ADD COLUMN IF NOT EXISTS creative_drive TEXT DEFAULT ''"); } catch(e) {}
  console.log('Database ready');
}

function enrichItems(items, users) {
  const map = {}; users.forEach(u => { map[u.id] = u; });
  return items.map(item => ({ ...item, writer: map[item.content_writer_id]||null, designer: map[item.design_assignee_id]||null, creator: map[item.created_by]||null }));
}

function auth(req, res, next) {
  const token = (req.headers.authorization||'').replace('Bearer ','') || (req.cookies&&req.cookies.token) || '';
  if (!token) return res.status(401).json({ error: 'Not authenticated' });
  try { req.user = jwt.verify(token, SECRET); next(); }
  catch(e) { res.status(401).json({ error: 'Invalid token' }); }
}
function adminOnly(req, res, next) {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' }); next();
}

async function seedAdmin() {
  const existing = await queryOne('SELECT id FROM users LIMIT 1');
  if (!existing) {
    const hash = await bcrypt.hash('spyne2024', 10);
    await query('INSERT INTO users (id,name,email,password,role,avatar_color) VALUES ($1,$2,$3,$4,$5,$6)', [uuid(),'Admin','admin@spyne.ai',hash,'admin','#D94F04']);
    console.log('Default admin created: admin@spyne.ai / spyne2024');
  }
}

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email||!password) return res.status(400).json({ error: 'Email and password required' });
    const user = await queryOne('SELECT * FROM users WHERE LOWER(email)=LOWER($1)', [email]);
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });
    if (!await bcrypt.compare(password, user.password)) return res.status(401).json({ error: 'Invalid credentials' });
    const token = jwt.sign({ id:user.id, email:user.email, name:user.name, role:user.role }, SECRET, { expiresIn:'7d' });
    try { res.cookie('token', token, { httpOnly:true, maxAge:7*86400*1000, sameSite:'none', secure:true }); } catch(e) {}
    res.json({ token, user: { id:user.id, name:user.name, email:user.email, role:user.role, avatar_color:user.avatar_color } });
  } catch(e) { console.error(e); res.status(500).json({ error:'Server error' }); }
});

app.post('/api/auth/logout', (req, res) => { res.clearCookie('token'); res.json({ ok:true }); });

app.get('/api/auth/me', auth, async (req, res) => {
  try {
    const user = await queryOne('SELECT id,name,email,role,avatar_color FROM users WHERE id=$1', [req.user.id]);
    if (!user) return res.status(404).json({ error:'User not found' });
    res.json(user);
  } catch(e) { res.status(500).json({ error:'Server error' }); }
});

app.get('/api/users', auth, async (req, res) => {
  try { res.json(await query('SELECT id,name,email,role,avatar_color,created_at FROM users ORDER BY name')); }
  catch(e) { res.status(500).json({ error:'Server error' }); }
});

app.post('/api/users', auth, adminOnly, async (req, res) => {
  try {
    const { name, email, password, role, avatar_color } = req.body;
    if (!name||!email||!password||!role) return res.status(400).json({ error:'Missing fields' });
    if (await queryOne('SELECT id FROM users WHERE LOWER(email)=LOWER($1)',[email])) return res.status(409).json({ error:'Email already in use' });
    const id = uuid();
    await query('INSERT INTO users (id,name,email,password,role,avatar_color) VALUES ($1,$2,$3,$4,$5,$6)', [id,name,email,await bcrypt.hash(password,10),role,avatar_color||'#D94F04']);
    res.json({ ok:true, id });
  } catch(e) { console.error(e); res.status(500).json({ error:'Server error' }); }
});

app.put('/api/users/:id', auth, async (req, res) => {
  try {
    const isOwn = req.user.id===req.params.id, isAdmin = req.user.role==='admin';
    if (!isOwn&&!isAdmin) return res.status(403).json({ error:'Forbidden' });
    const user = await queryOne('SELECT * FROM users WHERE id=$1',[req.params.id]);
    if (!user) return res.status(404).json({ error:'Not found' });
    const { name, avatar_color, password, role } = req.body;
    await query('UPDATE users SET name=$1,avatar_color=$2,role=$3,password=$4 WHERE id=$5',
      [name||user.name, avatar_color||user.avatar_color, (isAdmin&&role)?role:user.role, password?await bcrypt.hash(password,10):user.password, req.params.id]);
    res.json({ ok:true });
  } catch(e) { res.status(500).json({ error:'Server error' }); }
});

app.delete('/api/users/:id', auth, adminOnly, async (req, res) => {
  try {
    if (req.params.id===req.user.id) return res.status(400).json({ error:'Cannot delete yourself' });
    await query('DELETE FROM users WHERE id=$1',[req.params.id]); res.json({ ok:true });
  } catch(e) { res.status(500).json({ error:'Server error' }); }
});

app.get('/api/items', auth, async (req, res) => {
  try {
    let sql = 'SELECT * FROM content_items WHERE 1=1', params = [];
    if (req.user.role==='design') { sql+=' AND design_assignee_id=$1'; params.push(req.user.id); }
    sql += ' ORDER BY created_at DESC';
    const [items, users] = await Promise.all([query(sql,params), query('SELECT id,name,avatar_color,role FROM users')]);
    res.json(enrichItems(items, users));
  } catch(e) { console.error(e); res.status(500).json({ error:'Server error' }); }
});

app.post('/api/items', auth, async (req, res) => {
  try {
    if (!['admin','content'].includes(req.user.role)) return res.status(403).json({ error:'Forbidden' });
    const { keywords,type,category,cluster,ams,content_status,content_writer_id,content_delivery_date,seo_assigned_date,design_status,design_assignee_id,design_assign_date,design_delivery_date,overall_status,approved,live_url,new_content_link,notes,doc_link,images_needed,creative_drive } = req.body;
    if (!keywords) return res.status(400).json({ error:'keywords required' });
    const id = uuid();
    await query(`INSERT INTO content_items (id,keywords,type,category,cluster,ams,content_status,content_writer_id,content_delivery_date,seo_assigned_date,design_status,design_assignee_id,design_assign_date,design_delivery_date,overall_status,approved,live_url,new_content_link,notes,doc_link,images_needed,creative_drive,created_by) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23)`,
      [id,keywords,type||'',category||'',cluster||'',ams||'',content_status||'Not Started',content_writer_id||'',content_delivery_date||'',seo_assigned_date||'',design_status||'Not Assigned',design_assignee_id||'',design_assign_date||'',design_delivery_date||'',overall_status||'In Progress',approved||'',live_url||'',new_content_link||'',notes||'',doc_link||'',images_needed||'',creative_drive||'',req.user.id]);
    await query('INSERT INTO activity_log (id,item_id,user_id,user_name,action,details) VALUES ($1,$2,$3,$4,$5,$6)',[uuid(),id,req.user.id,req.user.name,'created',`Created "${keywords}"`]);
    const [item, users] = await Promise.all([queryOne('SELECT * FROM content_items WHERE id=$1',[id]), query('SELECT id,name,avatar_color,role FROM users')]);
    res.json(enrichItems([item],users)[0]);
  } catch(e) { console.error(e); res.status(500).json({ error:e.message }); }
});

app.put('/api/items/:id', auth, async (req, res) => {
  try {
    const item = await queryOne('SELECT * FROM content_items WHERE id=$1',[req.params.id]);
    if (!item) return res.status(404).json({ error:'Not found' });
    const allFields = ['keywords','type','category','cluster','ams','content_status','content_writer_id','content_delivery_date','seo_assigned_date','design_status','design_assignee_id','design_assign_date','design_delivery_date','overall_status','approved','live_url','new_content_link','notes','doc_link','images_needed','creative_drive'];
    let fields = req.user.role==='design' ? ['design_status','design_delivery_date','notes','creative_drive'] : allFields;
    if (req.user.role==='design' && req.body.design_status==='Design Done') { req.body.overall_status='Content Done'; fields=[...fields,'overall_status']; }
    const sets=[], params=[];
    let i=1;
    fields.forEach(f => { if (req.body[f]!==undefined) { sets.push(`${f}=$${i++}`); params.push(req.body[f]); } });
    if (!sets.length) return res.status(400).json({ error:'Nothing to update' });
    sets.push('updated_at=NOW()'); params.push(req.params.id);
    await query(`UPDATE content_items SET ${sets.join(',')} WHERE id=$${i}`, params);
    await query('INSERT INTO activity_log (id,item_id,user_id,user_name,action,details) VALUES ($1,$2,$3,$4,$5,$6)',[uuid(),req.params.id,req.user.id,req.user.name,'updated',JSON.stringify(req.body)]);
    const [updated, users] = await Promise.all([queryOne('SELECT * FROM content_items WHERE id=$1',[req.params.id]), query('SELECT id,name,avatar_color,role FROM users')]);
    res.json(enrichItems([updated],users)[0]);
  } catch(e) { console.error(e); res.status(500).json({ error:e.message }); }
});

app.delete('/api/items/:id', auth, adminOnly, async (req, res) => {
  try { await query('DELETE FROM content_items WHERE id=$1',[req.params.id]); res.json({ ok:true }); }
  catch(e) { res.status(500).json({ error:'Server error' }); }
});

app.get('/api/items/:id/activity', auth, async (req, res) => {
  try { res.json(await query('SELECT * FROM activity_log WHERE item_id=$1 ORDER BY created_at DESC LIMIT 10',[req.params.id])); }
  catch(e) { res.status(500).json({ error:'Server error' }); }
});

app.get('/api/stats', auth, async (req, res) => {
  try {
    const [total,published,designDone,inProgress,byType,byWriter] = await Promise.all([
      queryOne('SELECT COUNT(*) as n FROM content_items'),
      queryOne("SELECT COUNT(*) as n FROM content_items WHERE overall_status='Published'"),
      queryOne("SELECT COUNT(*) as n FROM content_items WHERE design_status='Design Done'"),
      queryOne("SELECT COUNT(*) as n FROM content_items WHERE overall_status='In Progress'"),
      query("SELECT type, COUNT(*) as count FROM content_items WHERE type!='' GROUP BY type ORDER BY count DESC"),
      query("SELECT u.name, COUNT(*) as count FROM content_items ci JOIN users u ON ci.content_writer_id=u.id WHERE ci.content_writer_id!='' GROUP BY u.id,u.name ORDER BY count DESC LIMIT 8")
    ]);
    res.json({ total:parseInt(total?.n||0), published:parseInt(published?.n||0), designDone:parseInt(designDone?.n||0), inProgress:parseInt(inProgress?.n||0), byType, byWriter });
  } catch(e) { res.status(500).json({ error:'Server error' }); }
});

app.get('/api/health', (req, res) => res.json({ ok:true }));

app.use((req, res) => {
  if (req.path.startsWith('/api/')) return res.status(404).json({ error:'Not found' });
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

initDB().then(async () => {
  await seedAdmin();
  app.listen(PORT, () => console.log(`Spyne Tracker running on port ${PORT}`));
}).catch(err => { console.error('DB init failed:', err.message); process.exit(1); });
