require('dotenv').config();
console.log('Starting Rose Shop backend...');
console.log('SUPABASE_URL set:', !!process.env.SUPABASE_URL);
console.log('SUPABASE_SERVICE_KEY set:', !!process.env.SUPABASE_SERVICE_KEY);
console.log('JWT_SECRET set:', !!process.env.JWT_SECRET);

const express = require('express');
console.log('express loaded');
const path = require('path');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { createClient } = require('@supabase/supabase-js');
console.log('all modules loaded');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'change-this-secret-in-production';

// Supabase client using the SECRET service_role key (server-side only, full access)
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);
console.log('supabase client created');

app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname)));

// ── HELPERS ──
function makeToken(user) {
  return jwt.sign({ id: user.id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '30d' });
}

function authMiddleware(req, res, next) {
  const token = req.cookies.rose_token;
  if (!token) return res.status(401).json({ error: 'Not logged in' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Invalid session' });
  }
}

// ── AUTH ROUTES ──

// REGISTER
app.post('/api/register', async (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !email || !password) {
    return res.status(400).json({ error: 'All fields required' });
  }
  if (password.length < 6) {
    return res.status(400).json({ error: 'Password must be at least 6 characters' });
  }

  // check existing
  const { data: existing } = await supabase
    .from('users')
    .select('id')
    .or(`username.eq.${username},email.eq.${email}`)
    .maybeSingle();

  if (existing) {
    return res.status(400).json({ error: 'Username or email already taken' });
  }

  const password_hash = await bcrypt.hash(password, 10);

  const { data: user, error } = await supabase
    .from('users')
    .insert({ username, email, password_hash, role: 'user' })
    .select()
    .single();

  if (error) return res.status(500).json({ error: error.message });

  const token = makeToken(user);
  res.cookie('rose_token', token, { httpOnly: true, maxAge: 30 * 24 * 60 * 60 * 1000, sameSite: 'lax' });
  res.json({ success: true, user: { id: user.id, username: user.username, role: user.role } });
});

// LOGIN
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Missing credentials' });

  const { data: user } = await supabase
    .from('users')
    .select('*')
    .or(`username.eq.${username},email.eq.${username}`)
    .maybeSingle();

  if (!user) return res.status(401).json({ error: 'Invalid username/email or password' });
  if (user.banned) return res.status(403).json({ error: 'This account has been banned' });

  const valid = await bcrypt.compare(password, user.password_hash);
  if (!valid) return res.status(401).json({ error: 'Invalid username/email or password' });

  const token = makeToken(user);
  res.cookie('rose_token', token, { httpOnly: true, maxAge: 30 * 24 * 60 * 60 * 1000, sameSite: 'lax' });
  res.json({
    success: true,
    user: { id: user.id, username: user.username, role: user.role, bio: user.bio, country: user.country }
  });
});

// LOGOUT
app.post('/api/logout', (req, res) => {
  res.clearCookie('rose_token');
  res.json({ success: true });
});

// ME (check current session)
app.get('/api/me', authMiddleware, async (req, res) => {
  const { data: user, error } = await supabase
    .from('users')
    .select('id, username, role, bio, age, country, timezone, avatar_url, banned')
    .eq('id', req.user.id)
    .single();

  if (error || !user) return res.status(401).json({ error: 'Session invalid' });
  if (user.banned) return res.status(403).json({ error: 'Account banned' });

  res.json({ user });
});

// ── LICENSE ROUTES ──

// Claim a key
app.post('/api/claim-key', authMiddleware, async (req, res) => {
  const { key } = req.body;
  if (!key) return res.status(400).json({ error: 'Key required' });

  const { data: license } = await supabase
    .from('licenses')
    .select('*')
    .eq('key', key.toUpperCase())
    .maybeSingle();

  if (!license) return res.status(404).json({ error: 'Invalid key' });
  if (license.status !== 'unclaimed') return res.status(400).json({ error: 'Key already used or suspended' });

  const expires_at = license.plan === 'Lifetime'
    ? null
    : new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();

  const { error } = await supabase
    .from('licenses')
    .update({ status: 'claimed', user_id: req.user.id, claimed_at: new Date().toISOString(), expires_at })
    .eq('id', license.id);

  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true, license: { ...license, status: 'claimed' } });
});

// Get my license
app.get('/api/my-license', authMiddleware, async (req, res) => {
  const { data } = await supabase
    .from('licenses')
    .select('*')
    .eq('user_id', req.user.id)
    .eq('status', 'claimed')
    .maybeSingle();
  res.json({ license: data || null });
});

// ── ADMIN: KEY MANAGEMENT ──
function requireAdmin(req, res, next) {
  if (!['admin', 'owner'].includes(req.user.role)) return res.status(403).json({ error: 'Admins only' });
  next();
}

app.post('/api/admin/add-key', authMiddleware, requireAdmin, async (req, res) => {
  const { key, product, plan } = req.body;
  const { data, error } = await supabase
    .from('licenses')
    .insert({ key: key.toUpperCase(), product, plan, status: 'unclaimed' })
    .select()
    .single();
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true, license: data });
});

app.get('/api/admin/keys', authMiddleware, requireAdmin, async (req, res) => {
  const { data, error } = await supabase.from('licenses').select('*, users(username)').order('created_at', { ascending: false });
  if (error) return res.status(500).json({ error: error.message });
  res.json({ keys: data });
});

app.post('/api/admin/suspend-key/:id', authMiddleware, requireAdmin, async (req, res) => {
  const { data: current } = await supabase.from('licenses').select('status').eq('id', req.params.id).single();
  const newStatus = current.status === 'suspended' ? 'claimed' : 'suspended';
  const { error } = await supabase.from('licenses').update({ status: newStatus }).eq('id', req.params.id);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true, status: newStatus });
});

app.delete('/api/admin/delete-key/:id', authMiddleware, requireAdmin, async (req, res) => {
  const { data: current, error: findErr } = await supabase
    .from('licenses')
    .select('status')
    .eq('id', req.params.id)
    .maybeSingle();

  if (findErr) return res.status(500).json({ error: findErr.message });
  if (!current) return res.status(404).json({ error: 'Key not found' });

  // Don't allow deleting a key that's already claimed by a customer —
  // suspend it instead so their access record stays intact.
  if (current.status === 'claimed') {
    return res.status(400).json({ error: 'Cannot delete a claimed key. Suspend it instead.' });
  }

  const { error } = await supabase.from('licenses').delete().eq('id', req.params.id);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true });
});

// ── ADMIN: USER MANAGEMENT ──
app.get('/api/admin/users', authMiddleware, requireAdmin, async (req, res) => {
  const { data, error } = await supabase.from('users').select('id, username, email, role, banned, created_at, timeout_until');
  if (error) return res.status(500).json({ error: error.message });
  res.json({ users: data });
});

app.post('/api/admin/ban/:id', authMiddleware, requireAdmin, async (req, res) => {
  const { data: target } = await supabase.from('users').select('role').eq('id', req.params.id).single();
  if (target.role === 'owner' && req.user.role !== 'owner') {
    return res.status(403).json({ error: 'Cannot ban an owner' });
  }
  const { error } = await supabase.from('users').update({ banned: true }).eq('id', req.params.id);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true });
});

app.post('/api/admin/unban/:id', authMiddleware, requireAdmin, async (req, res) => {
  const { error } = await supabase.from('users').update({ banned: false }).eq('id', req.params.id);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true });
});

app.post('/api/admin/promote/:id', authMiddleware, requireAdmin, async (req, res) => {
  const { error } = await supabase.from('users').update({ role: 'admin' }).eq('id', req.params.id);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true });
});

// ── FALLBACK: serve index.html for the root ──
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, () => {
  console.log(`Rose Shop backend running on port ${PORT}`);
});

process.on('uncaughtException', (err) => {
  console.error('UNCAUGHT EXCEPTION:', err);
});
process.on('unhandledRejection', (err) => {
  console.error('UNHANDLED REJECTION:', err);
});
