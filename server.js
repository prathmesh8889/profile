'use strict';

const path = require('path');
const crypto = require('crypto');
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');

const app = express();
app.set('trust proxy', 1);
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'"],
      imgSrc: ["'self'", 'data:'],
      connectSrc: ["'self'"],
      objectSrc: ["'none'"],
      baseUri: ["'self'"],
      frameAncestors: ["'none'"]
    }
  }
}));
app.use(express.json({ limit: '64kb' }));
app.use(express.urlencoded({ extended: false, limit: '64kb' }));

const DATABASE_URL = process.env.DATABASE_URL;
const JWT_SECRET = process.env.JWT_SECRET;
const PORT = Number(process.env.PORT || 3000);

if (!DATABASE_URL) {
  console.error('DATABASE_URL is required.');
  process.exit(1);
}
if (!JWT_SECRET || JWT_SECRET.length < 32) {
  console.error('JWT_SECRET must be at least 32 characters.');
  process.exit(1);
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: process.env.DB_SSL === 'true' ? { rejectUnauthorized: false } : false,
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 30,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  message: { error: 'Too many authentication attempts. Please try again later.' }
});
const contactLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  limit: 20,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  message: { error: 'Too many requests. Please try again later.' }
});

function cleanText(value, max = 500) { return String(value ?? '').trim().slice(0, max); }
function cleanEmail(value) { return cleanText(value, 254).toLowerCase(); }
function validEmail(email) { return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email); }
function signToken(user) {
  return jwt.sign({ sub: String(user.id), role: user.role, email: user.email }, JWT_SECRET, { expiresIn: '8h', issuer: 'securelife-insurance' });
}
function publicUser(user) { return { id: user.id, name: user.name, email: user.email, role: user.role }; }
function authRequired(req, res, next) {
  const header = req.get('authorization') || '';
  const [scheme, token] = header.split(' ');
  if (scheme !== 'Bearer' || !token) return res.status(401).json({ error: 'Authentication required.' });
  try {
    req.auth = jwt.verify(token, JWT_SECRET, { issuer: 'securelife-insurance' });
    return next();
  } catch {
    return res.status(401).json({ error: 'Session expired or invalid.' });
  }
}
function adminRequired(req, res, next) {
  if (req.auth?.role !== 'ADMIN') return res.status(403).json({ error: 'Admin access required.' });
  next();
}
function optionalAuth(req, _res, next) {
  const header = req.get('authorization') || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (token) {
    try { req.auth = jwt.verify(token, JWT_SECRET, { issuer: 'securelife-insurance' }); } catch {}
  }
  next();
}
function money(value) {
  const n = Number(value);
  return Number.isFinite(n) && n >= 0 ? Math.round(n * 100) / 100 : null;
}
function futureDate(days = 365) {
  const d = new Date();
  d.setUTCDate(d.getUTCDate() + days);
  return d.toISOString().slice(0, 10);
}
function makePolicyNumber(id) { return `SL-${new Date().getUTCFullYear()}-${String(id).padStart(6, '0')}`; }
function makeReference() { return `PAY-${Date.now()}-${crypto.randomBytes(4).toString('hex').toUpperCase()}`; }

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      name VARCHAR(100) NOT NULL,
      email VARCHAR(254) UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role VARCHAR(20) NOT NULL DEFAULT 'USER' CHECK (role IN ('USER','ADMIN')),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS policies (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      policy_number VARCHAR(40) UNIQUE,
      policy_type VARCHAR(50) NOT NULL,
      plan VARCHAR(50) NOT NULL,
      coverage NUMERIC(14,2) NOT NULL CHECK (coverage > 0),
      premium NUMERIC(12,2),
      status VARCHAR(30) NOT NULL DEFAULT 'Pending' CHECK (status IN ('Pending','Active','Rejected','Expired','Cancelled')),
      renewal_date DATE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS idx_policies_user_id ON policies(user_id);
    CREATE TABLE IF NOT EXISTS claims (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      policy_id INTEGER NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
      description VARCHAR(1000) NOT NULL,
      amount NUMERIC(12,2) NOT NULL CHECK (amount > 0),
      status VARCHAR(30) NOT NULL DEFAULT 'Submitted' CHECK (status IN ('Submitted','Under Review','Approved','Rejected','Paid')),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS idx_claims_user_id ON claims(user_id);
    CREATE TABLE IF NOT EXISTS payments (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      policy_id INTEGER NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
      amount NUMERIC(12,2) NOT NULL CHECK (amount > 0),
      reference VARCHAR(80) UNIQUE NOT NULL,
      status VARCHAR(20) NOT NULL DEFAULT 'Recorded' CHECK (status IN ('Recorded','Verified','Rejected')),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS idx_payments_user_id ON payments(user_id);
    CREATE TABLE IF NOT EXISTS contacts (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
      name VARCHAR(100) NOT NULL,
      email VARCHAR(254) NOT NULL,
      phone VARCHAR(30),
      insurance VARCHAR(60),
      message VARCHAR(1500) NOT NULL,
      status VARCHAR(20) NOT NULL DEFAULT 'New' CHECK (status IN ('New','Contacted','Closed')),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  const adminEmail = cleanEmail(process.env.ADMIN_EMAIL);
  const adminPassword = process.env.ADMIN_PASSWORD || '';
  if (adminEmail && adminPassword.length >= 10 && validEmail(adminEmail)) {
    const hash = await bcrypt.hash(adminPassword, 12);
    await pool.query(`
      INSERT INTO users(name, email, password_hash, role)
      VALUES($1, $2, $3, 'ADMIN')
      ON CONFLICT(email) DO UPDATE SET role='ADMIN'
    `, ['Administrator', adminEmail, hash]);
  }
}

app.get('/api/health', async (_req, res) => {
  try {
    const { rows } = await pool.query('SELECT NOW() AS now');
    res.json({ ok: true, database: 'connected', time: rows[0].now });
  } catch {
    res.status(503).json({ ok: false, database: 'unavailable' });
  }
});

app.post('/api/auth/register', authLimiter, async (req, res) => {
  const name = cleanText(req.body.name, 100);
  const email = cleanEmail(req.body.email);
  const password = String(req.body.password || '');
  if (name.length < 2) return res.status(400).json({ error: 'Name must contain at least 2 characters.' });
  if (!validEmail(email)) return res.status(400).json({ error: 'Enter a valid email address.' });
  if (password.length < 8 || password.length > 128) return res.status(400).json({ error: 'Password must be 8-128 characters.' });
  try {
    const hash = await bcrypt.hash(password, 12);
    const { rows } = await pool.query(
      `INSERT INTO users(name,email,password_hash,role) VALUES($1,$2,$3,'USER') RETURNING id,name,email,role`,
      [name, email, hash]
    );
    const user = rows[0];
    res.status(201).json({ token: signToken(user), user: publicUser(user) });
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'An account with this email already exists.' });
    console.error(err);
    res.status(500).json({ error: 'Could not create account.' });
  }
});

app.post('/api/auth/login', authLimiter, async (req, res) => {
  const email = cleanEmail(req.body.email);
  const password = String(req.body.password || '');
  if (!validEmail(email) || !password) return res.status(400).json({ error: 'Email and password are required.' });
  const { rows } = await pool.query('SELECT id,name,email,password_hash,role FROM users WHERE email=$1', [email]);
  const user = rows[0];
  if (!user || !(await bcrypt.compare(password, user.password_hash))) return res.status(401).json({ error: 'Invalid email or password.' });
  res.json({ token: signToken(user), user: publicUser(user) });
});

app.get('/api/me', authRequired, async (req, res) => {
  const { rows } = await pool.query('SELECT id,name,email,role,created_at FROM users WHERE id=$1', [req.auth.sub]);
  if (!rows[0]) return res.status(404).json({ error: 'User not found.' });
  res.json(rows[0]);
});

app.put('/api/me/password', authRequired, authLimiter, async (req, res) => {
  const currentPassword = String(req.body.currentPassword || '');
  const newPassword = String(req.body.newPassword || '');
  if (newPassword.length < 8 || newPassword.length > 128) return res.status(400).json({ error: 'New password must be 8-128 characters.' });
  const { rows } = await pool.query('SELECT password_hash FROM users WHERE id=$1', [req.auth.sub]);
  if (!rows[0] || !(await bcrypt.compare(currentPassword, rows[0].password_hash))) return res.status(400).json({ error: 'Current password is incorrect.' });
  const hash = await bcrypt.hash(newPassword, 12);
  await pool.query('UPDATE users SET password_hash=$1 WHERE id=$2', [hash, req.auth.sub]);
  res.json({ message: 'Password updated successfully.' });
});

app.get('/api/policies', authRequired, async (req, res) => {
  const { rows } = await pool.query(
    `SELECT id,policy_number,policy_type,plan,coverage,premium,status,renewal_date,created_at FROM policies WHERE user_id=$1 ORDER BY created_at DESC`,
    [req.auth.sub]
  );
  res.json(rows);
});

app.post('/api/policies', authRequired, async (req, res) => {
  const allowedTypes = ['Life Insurance','Health Insurance','Car Insurance','Home Insurance','General Insurance'];
  const allowedPlans = ['Basic','Standard','Premium'];
  const policyType = cleanText(req.body.policyType, 50);
  const plan = cleanText(req.body.plan, 50);
  const coverage = money(req.body.coverage);
  if (!allowedTypes.includes(policyType) || !allowedPlans.includes(plan) || !coverage || coverage < 10000) {
    return res.status(400).json({ error: 'Choose a valid insurance type, plan and coverage of at least ₹10,000.' });
  }
  const { rows } = await pool.query(
    `INSERT INTO policies(user_id,policy_type,plan,coverage) VALUES($1,$2,$3,$4) RETURNING id,policy_number,policy_type,plan,coverage,premium,status,renewal_date,created_at`,
    [req.auth.sub, policyType, plan, coverage]
  );
  res.status(201).json({ message: 'Application submitted for review.', policy: rows[0] });
});

app.get('/api/claims', authRequired, async (req, res) => {
  const { rows } = await pool.query(
    `SELECT c.id,c.policy_id,p.policy_number,p.policy_type,c.description,c.amount,c.status,c.created_at
     FROM claims c JOIN policies p ON p.id=c.policy_id WHERE c.user_id=$1 ORDER BY c.created_at DESC`,
    [req.auth.sub]
  );
  res.json(rows);
});

app.post('/api/claims', authRequired, async (req, res) => {
  const policyId = Number(req.body.policyId);
  const description = cleanText(req.body.description, 1000);
  const amount = money(req.body.amount);
  if (!Number.isInteger(policyId) || description.length < 10 || !amount || amount <= 0) {
    return res.status(400).json({ error: 'Select an active policy, enter a description and valid claim amount.' });
  }
  const policy = await pool.query('SELECT id,status,coverage FROM policies WHERE id=$1 AND user_id=$2', [policyId, req.auth.sub]);
  if (!policy.rows[0] || policy.rows[0].status !== 'Active') return res.status(400).json({ error: 'Claims can only be submitted for an active policy.' });
  if (amount > Number(policy.rows[0].coverage)) return res.status(400).json({ error: 'Claim amount cannot exceed policy coverage.' });
  const { rows } = await pool.query(
    `INSERT INTO claims(user_id,policy_id,description,amount) VALUES($1,$2,$3,$4) RETURNING *`,
    [req.auth.sub, policyId, description, amount]
  );
  res.status(201).json({ message: 'Claim submitted.', claim: rows[0] });
});

app.get('/api/payments', authRequired, async (req, res) => {
  const { rows } = await pool.query(
    `SELECT py.id,py.policy_id,p.policy_number,p.policy_type,py.amount,py.reference,py.status,py.created_at
     FROM payments py JOIN policies p ON p.id=py.policy_id WHERE py.user_id=$1 ORDER BY py.created_at DESC`,
    [req.auth.sub]
  );
  res.json(rows);
});

app.post('/api/payments', authRequired, async (req, res) => {
  const policyId = Number(req.body.policyId);
  const amount = money(req.body.amount);
  if (!Number.isInteger(policyId) || !amount || amount <= 0) return res.status(400).json({ error: 'Select a policy and enter a valid amount.' });
  const policy = await pool.query('SELECT id,status,premium FROM policies WHERE id=$1 AND user_id=$2', [policyId, req.auth.sub]);
  if (!policy.rows[0] || policy.rows[0].status !== 'Active') return res.status(400).json({ error: 'Payment can only be recorded for an active policy.' });
  const reference = makeReference();
  const { rows } = await pool.query(
    `INSERT INTO payments(user_id,policy_id,amount,reference) VALUES($1,$2,$3,$4) RETURNING *`,
    [req.auth.sub, policyId, amount, reference]
  );
  res.status(201).json({ message: 'Payment record submitted for verification. No money was charged by this portal.', payment: rows[0] });
});

app.post('/api/contacts', contactLimiter, optionalAuth, async (req, res) => {
  const name = cleanText(req.body.name, 100);
  const email = cleanEmail(req.body.email);
  const phone = cleanText(req.body.phone, 30);
  const insurance = cleanText(req.body.insurance, 60);
  const message = cleanText(req.body.message, 1500);
  if (name.length < 2 || !validEmail(email) || message.length < 10) return res.status(400).json({ error: 'Name, valid email and a message of at least 10 characters are required.' });
  await pool.query(
    `INSERT INTO contacts(user_id,name,email,phone,insurance,message) VALUES($1,$2,$3,$4,$5,$6)`,
    [req.auth?.sub || null, name, email, phone || null, insurance || null, message]
  );
  res.status(201).json({ message: 'Thanks. Your enquiry has been received.' });
});

app.get('/api/admin/stats', authRequired, adminRequired, async (_req, res) => {
  const { rows } = await pool.query(`
    SELECT
      (SELECT COUNT(*)::int FROM users WHERE role='USER') users,
      (SELECT COUNT(*)::int FROM policies) policies,
      (SELECT COUNT(*)::int FROM policies WHERE status='Pending') pending_policies,
      (SELECT COUNT(*)::int FROM claims WHERE status IN ('Submitted','Under Review')) open_claims,
      (SELECT COUNT(*)::int FROM contacts WHERE status='New') new_contacts
  `);
  res.json(rows[0]);
});

app.get('/api/admin/users', authRequired, adminRequired, async (_req, res) => {
  const { rows } = await pool.query('SELECT id,name,email,role,created_at FROM users ORDER BY created_at DESC');
  res.json(rows);
});

app.get('/api/admin/policies', authRequired, adminRequired, async (_req, res) => {
  const { rows } = await pool.query(`
    SELECT p.*,u.name user_name,u.email user_email FROM policies p
    JOIN users u ON u.id=p.user_id ORDER BY p.created_at DESC
  `);
  res.json(rows);
});

app.patch('/api/admin/policies/:id', authRequired, adminRequired, async (req, res) => {
  const id = Number(req.params.id);
  const status = cleanText(req.body.status, 30);
  const allowed = ['Pending','Active','Rejected','Expired','Cancelled'];
  const premium = req.body.premium === '' || req.body.premium == null ? null : money(req.body.premium);
  let renewalDate = cleanText(req.body.renewalDate, 10) || null;
  if (!Number.isInteger(id) || !allowed.includes(status) || (premium !== null && premium <= 0)) return res.status(400).json({ error: 'Invalid policy update.' });
  const existing = await pool.query('SELECT * FROM policies WHERE id=$1', [id]);
  if (!existing.rows[0]) return res.status(404).json({ error: 'Policy not found.' });
  let policyNumber = existing.rows[0].policy_number;
  if (status === 'Active' && !policyNumber) policyNumber = makePolicyNumber(id);
  if (status === 'Active' && !renewalDate) renewalDate = futureDate(365);
  const { rows } = await pool.query(
    `UPDATE policies SET status=$1,premium=$2,renewal_date=$3,policy_number=$4 WHERE id=$5 RETURNING *`,
    [status, premium, renewalDate, policyNumber, id]
  );
  res.json({ message: 'Policy updated.', policy: rows[0] });
});

app.get('/api/admin/claims', authRequired, adminRequired, async (_req, res) => {
  const { rows } = await pool.query(`
    SELECT c.*,p.policy_number,p.policy_type,u.name user_name,u.email user_email
    FROM claims c JOIN policies p ON p.id=c.policy_id JOIN users u ON u.id=c.user_id
    ORDER BY c.created_at DESC
  `);
  res.json(rows);
});

app.patch('/api/admin/claims/:id', authRequired, adminRequired, async (req, res) => {
  const id = Number(req.params.id);
  const status = cleanText(req.body.status, 30);
  const allowed = ['Submitted','Under Review','Approved','Rejected','Paid'];
  if (!Number.isInteger(id) || !allowed.includes(status)) return res.status(400).json({ error: 'Invalid claim update.' });
  const { rows } = await pool.query('UPDATE claims SET status=$1 WHERE id=$2 RETURNING *', [status, id]);
  if (!rows[0]) return res.status(404).json({ error: 'Claim not found.' });
  res.json({ message: 'Claim updated.', claim: rows[0] });
});

app.get('/api/admin/payments', authRequired, adminRequired, async (_req, res) => {
  const { rows } = await pool.query(`
    SELECT py.*,p.policy_number,u.name user_name,u.email user_email
    FROM payments py JOIN policies p ON p.id=py.policy_id JOIN users u ON u.id=py.user_id
    ORDER BY py.created_at DESC
  `);
  res.json(rows);
});

app.patch('/api/admin/payments/:id', authRequired, adminRequired, async (req, res) => {
  const id = Number(req.params.id);
  const status = cleanText(req.body.status, 20);
  const allowed = ['Recorded','Verified','Rejected'];
  if (!Number.isInteger(id) || !allowed.includes(status)) return res.status(400).json({ error: 'Invalid payment update.' });
  const { rows } = await pool.query('UPDATE payments SET status=$1 WHERE id=$2 RETURNING *', [status, id]);
  if (!rows[0]) return res.status(404).json({ error: 'Payment not found.' });
  res.json({ message: 'Payment updated.', payment: rows[0] });
});

app.get('/api/admin/contacts', authRequired, adminRequired, async (_req, res) => {
  const { rows } = await pool.query('SELECT * FROM contacts ORDER BY created_at DESC');
  res.json(rows);
});

app.patch('/api/admin/contacts/:id', authRequired, adminRequired, async (req, res) => {
  const id = Number(req.params.id);
  const status = cleanText(req.body.status, 20);
  if (!Number.isInteger(id) || !['New','Contacted','Closed'].includes(status)) return res.status(400).json({ error: 'Invalid contact update.' });
  const { rows } = await pool.query('UPDATE contacts SET status=$1 WHERE id=$2 RETURNING *', [status, id]);
  if (!rows[0]) return res.status(404).json({ error: 'Enquiry not found.' });
  res.json({ message: 'Enquiry updated.' });
});

app.use(express.static(path.join(__dirname, 'public'), {
  extensions: ['html'],
  maxAge: process.env.NODE_ENV === 'production' ? '1h' : 0
}));

app.get('/{*splat}', (_req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

app.use((err, _req, res, _next) => {
  console.error(err);
  res.status(500).json({ error: 'Unexpected server error.' });
});

initDb()
  .then(() => app.listen(PORT, '0.0.0.0', () => console.log(`SecureLife running on port ${PORT}`)))
  .catch((err) => {
    console.error('Database initialization failed:', err);
    process.exit(1);
  });
