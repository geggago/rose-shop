require('dotenv').config();
console.log('Starting Rose Shop backend...');
console.log('SUPABASE_URL set:', !!process.env.SUPABASE_URL);
console.log('SUPABASE_SERVICE_KEY set:', !!process.env.SUPABASE_SERVICE_KEY);
console.log('JWT_SECRET set:', !!process.env.JWT_SECRET);
console.log('STRIPE_SECRET_KEY set:', !!process.env.STRIPE_SECRET_KEY);
console.log('RESEND_API_KEY set:', !!process.env.RESEND_API_KEY);

const express = require('express');
console.log('express loaded');
const path = require('path');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { createClient } = require('@supabase/supabase-js');
const Stripe = require('stripe');
const { Resend } = require('resend');
console.log('all modules loaded');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'change-this-secret-in-production';
const stripe = Stripe(process.env.STRIPE_SECRET_KEY);
const resend = new Resend(process.env.RESEND_API_KEY);
const SITE_URL = 'https://www.rose-software.store';

// Supabase client using the SECRET service_role key (server-side only, full access)
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);
console.log('supabase client created');

// Stripe webhook needs raw body — must be BEFORE express.json()
app.use('/api/stripe/webhook', express.raw({ type: 'application/json' }));

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

// Public stock counts only — no auth required, no key values or user data exposed.
// This is what the shop page (visible to guests/customers) should use, NOT /api/admin/keys.
app.get('/api/stock', async (req, res) => {
  const { data, error } = await supabase
    .from('licenses')
    .select('product, plan, status')
    .eq('status', 'unclaimed');

  if (error) return res.status(500).json({ error: error.message });

  const counts = {};
  for (const row of data) {
    const k = `${row.product}::${row.plan}`;
    counts[k] = (counts[k] || 0) + 1;
  }

  res.json({ counts }); // e.g. { "Rose Executor::Free Trial": 3, "Rose Executor::Lifetime": 2 }
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
  if (target.role === 'admin' && req.user.role !== 'owner') {
    return res.status(403).json({ error: 'Only an owner can ban an admin' });
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

app.post('/api/admin/timeout/:id', authMiddleware, requireAdmin, async (req, res) => {
  const { data: target } = await supabase.from('users').select('role').eq('id', req.params.id).single();
  if (['owner','admin'].includes(target.role) && req.user.role !== 'owner') {
    return res.status(403).json({ error: 'Only an owner can timeout staff' });
  }
  const minutes = Number(req.body.minutes) || 10;
  const timeout_until = new Date(Date.now() + minutes * 60 * 1000).toISOString();
  const { error } = await supabase.from('users').update({ timeout_until }).eq('id', req.params.id);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true, timeout_until });
});

// Owner-only: promoting to admin grants real admin powers, so only an owner can grant it.
app.post('/api/admin/promote/:id', authMiddleware, requireAdmin, async (req, res) => {
  if (req.user.role !== 'owner') {
    return res.status(403).json({ error: 'Only an owner can promote users to admin' });
  }
  const { error } = await supabase.from('users').update({ role: 'admin' }).eq('id', req.params.id);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true });
});

// ── FREE TRIAL: Claim via email (one per account) ──
app.post('/api/claim-free-trial', authMiddleware, async (req, res) => {
  const { email, emailConfirm } = req.body;

  if (!email || !emailConfirm) return res.status(400).json({ error: 'Both email fields are required.' });
  if (email.toLowerCase() !== emailConfirm.toLowerCase()) return res.status(400).json({ error: 'Emails do not match.' });

  // Check if this account already claimed a free trial
  const { data: existingTrial } = await supabase
    .from('licenses')
    .select('id')
    .eq('user_id', req.user.id)
    .eq('plan', 'Free Trial')
    .maybeSingle();

  if (existingTrial) return res.status(400).json({ error: 'Your account has already used a free trial.' });

  // Check stock
  const { data: license } = await supabase
    .from('licenses')
    .select('*')
    .eq('plan', 'Free Trial')
    .eq('status', 'unclaimed')
    .limit(1)
    .maybeSingle();

  if (!license) return res.status(400).json({ error: 'No free trial keys available right now. Check back later.' });

  // Claim the key (24h expiry)
  const expires_at = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
  const { error } = await supabase
    .from('licenses')
    .update({ status: 'claimed', user_id: req.user.id, claimed_at: new Date().toISOString(), expires_at })
    .eq('id', license.id);

  if (error) return res.status(500).json({ error: error.message });

  // Send email
  await resend.emails.send({
    from: 'Rose Shop <onboarding@resend.dev>',
    to: email,
    subject: '🌹 Your Rose Executor Free Trial Key',
    html: `
      <div style="font-family:sans-serif;max-width:520px;margin:0 auto;background:#080f1c;color:#e8f0ff;padding:32px;border-radius:12px;border:1px solid #1a2d4a;">
        <h1 style="color:#ff2255;font-size:1.4rem;margin-bottom:8px;">Rose Shop</h1>
        <h2 style="font-size:1.1rem;margin-bottom:24px;color:#e8f0ff;">Your Free Trial is ready!</h2>
        <p style="color:#6a8aaa;margin-bottom:24px;">Here is your 24-hour free trial key for <strong style="color:#e8f0ff;">Rose Executor</strong>:</p>
        <div style="background:#040810;border:1px solid #2a4a7a;border-radius:8px;padding:16px;text-align:center;margin-bottom:24px;">
          <div style="font-size:0.7rem;color:#6a8aaa;letter-spacing:0.1em;text-transform:uppercase;margin-bottom:8px;">License Key</div>
          <div style="font-family:monospace;font-size:1.1rem;color:#3d8ef0;letter-spacing:0.05em;">${license.key}</div>
        </div>
        <p style="color:#6a8aaa;margin-bottom:8px;font-size:0.85rem;">To activate:</p>
        <ol style="color:#6a8aaa;font-size:0.85rem;padding-left:20px;line-height:1.8;">
          <li>Go to <a href="${SITE_URL}" style="color:#3d8ef0;">${SITE_URL}</a> and log in</li>
          <li>Click the <strong style="color:#e8f0ff;">Licenses</strong> tab</li>
          <li>Enter your key and click <strong style="color:#e8f0ff;">Claim Key</strong></li>
        </ol>
        <div style="margin-top:24px;padding-top:16px;border-top:1px solid #1a2d4a;font-size:0.75rem;color:#334455;">
          <p>This key expires in 24 hours. One free trial per account.</p>
          <p>By using Rose Executor you agree to our <a href="${SITE_URL}" style="color:#3d8ef0;">Terms of Service</a>.</p>
        </div>
      </div>
    `,
  });

  res.json({ success: true });
});


app.post('/api/stripe/create-checkout', authMiddleware, async (req, res) => {
  const { plan } = req.body; // 'Free Trial' or 'Lifetime'

  if (plan === 'Free Trial') {
    return res.status(400).json({ error: 'Free trial uses key claiming, not Stripe.' });
  }

  // Check if user already has an active license
  const { data: existing } = await supabase
    .from('licenses')
    .select('id')
    .eq('user_id', req.user.id)
    .eq('status', 'claimed')
    .maybeSingle();

  if (existing) {
    return res.status(400).json({ error: 'You already have an active license.' });
  }

  // Check stock
  const { data: availableKey } = await supabase
    .from('licenses')
    .select('id')
    .eq('plan', 'Lifetime')
    .eq('status', 'unclaimed')
    .limit(1)
    .maybeSingle();

  if (!availableKey) {
    return res.status(400).json({ error: 'Out of stock. Please try again later.' });
  }

  // Get user email for prefill
  const { data: user } = await supabase
    .from('users')
    .select('email, username')
    .eq('id', req.user.id)
    .single();

  const session = await stripe.checkout.sessions.create({
    payment_method_types: ['card'],
    mode: 'payment',
    customer_email: user.email,
    line_items: [{
      price_data: {
        currency: 'usd',
        product_data: {
          name: 'Rose Executor — Lifetime',
          description: 'Lifetime license key. Full access, 100 cloud configs.',
        },
        unit_amount: 999, // $9.99
      },
      quantity: 1,
    }],
    metadata: {
      user_id: req.user.id,
      username: user.username,
      plan: 'Lifetime',
      product: 'Rose Executor',
    },
    success_url: SITE_URL + '/?payment=success',
    cancel_url: SITE_URL + '/?payment=cancelled',
  });

  res.json({ url: session.url });
});

// ── STRIPE: WEBHOOK ──
app.post('/api/stripe/webhook', async (req, res) => {
  const sig = req.headers['stripe-signature'];
  let event;

  try {
    event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    console.error('Webhook signature error:', err.message);
    return res.status(400).json({ error: 'Invalid signature' });
  }

  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;
    const { user_id, username, plan, product } = session.metadata;
    const customerEmail = session.customer_email || session.customer_details?.email;

    try {
      // Find an unclaimed key
      const { data: license } = await supabase
        .from('licenses')
        .select('*')
        .eq('plan', plan)
        .eq('status', 'unclaimed')
        .limit(1)
        .maybeSingle();

      if (!license) {
        console.error('No unclaimed key available for plan:', plan);
        return res.json({ received: true });
      }

      // Claim the key
      await supabase
        .from('licenses')
        .update({
          status: 'claimed',
          user_id,
          claimed_at: new Date().toISOString(),
          expires_at: null, // Lifetime = never expires
        })
        .eq('id', license.id);

      // Send confirmation email
      await resend.emails.send({
        from: 'Rose Shop <onboarding@resend.dev>',
        to: customerEmail,
        subject: '✅ Your Rose Executor License Key',
        html: `
          <div style="font-family:sans-serif;max-width:520px;margin:0 auto;background:#080f1c;color:#e8f0ff;padding:32px;border-radius:12px;border:1px solid #1a2d4a;">
            <h1 style="color:#ff2255;font-size:1.4rem;margin-bottom:8px;">Rose Shop</h1>
            <h2 style="font-size:1.1rem;margin-bottom:24px;color:#e8f0ff;">Your purchase is confirmed!</h2>

            <p style="color:#6a8aaa;margin-bottom:8px;">Hi <strong style="color:#e8f0ff;">${username}</strong>,</p>
            <p style="color:#6a8aaa;margin-bottom:24px;">Thank you for purchasing <strong style="color:#e8f0ff;">Rose Executor — ${plan}</strong>. Here is your license key:</p>

            <div style="background:#040810;border:1px solid #2a4a7a;border-radius:8px;padding:16px;text-align:center;margin-bottom:24px;">
              <div style="font-size:0.7rem;color:#6a8aaa;letter-spacing:0.1em;text-transform:uppercase;margin-bottom:8px;">License Key</div>
              <div style="font-family:monospace;font-size:1.1rem;color:#3d8ef0;letter-spacing:0.05em;">${license.key}</div>
            </div>

            <p style="color:#6a8aaa;margin-bottom:8px;font-size:0.85rem;">To activate:</p>
            <ol style="color:#6a8aaa;font-size:0.85rem;padding-left:20px;line-height:1.8;">
              <li>Go to <a href="${SITE_URL}" style="color:#3d8ef0;">${SITE_URL}</a> and log in</li>
              <li>Click the <strong style="color:#e8f0ff;">Licenses</strong> tab</li>
              <li>Enter your key in the claim field and click <strong style="color:#e8f0ff;">Claim Key</strong></li>
            </ol>

            <div style="margin-top:24px;padding-top:16px;border-top:1px solid #1a2d4a;font-size:0.75rem;color:#334455;">
              <p>Plan: ${plan} &nbsp;|&nbsp; Product: ${product} &nbsp;|&nbsp; Amount: $9.99</p>
              <p>By using Rose Executor you agree to our <a href="${SITE_URL}" style="color:#3d8ef0;">Terms of Service</a>. This software is for single-player use only.</p>
            </div>
          </div>
        `,
      });

      console.log('License claimed and email sent to:', customerEmail);
    } catch (err) {
      console.error('Error processing webhook:', err);
    }
  }

  res.json({ received: true });
});


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
