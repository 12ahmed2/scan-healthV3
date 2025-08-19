// server.js
const express = require('express');
const { Pool } = require('pg');
const path = require('path');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcrypt');
const ms = require('ms');
const compression = require('compression');
const helmet = require('helmet');

const {
  issueTokens, requireAuth, refreshTokens, logout
} = require('./auth');

const authCheck = require('./middleware/authCheck.js'); // NEW LINE

require('dotenv').config();
const app = express();

app.use(compression());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

const pool = require('./db.js');

app.use(helmet({
  contentSecurityPolicy: {
    useDefaults: true,
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "https://cdn.jsdelivr.net"],
      scriptSrcElem: ["'self'", "https://cdn.jsdelivr.net"], // some browsers check this
      workerSrc: ["'self'", "blob:"],
      childSrc: ["'self'", "blob:"],
      connectSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "blob:"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      objectSrc: ["'none'"],
      baseUri: ["'self'"]
    }
  }
}));

// Health check
app.get('/dbhealth', async (req, res) => {
  try {
    const r = await pool.query('SELECT 1 AS ok');
    res.json({ db: 'up', result: r.rows[0] });
  } catch (e) {
    res.status(500).json({ db: 'down', error: e.message });
  }
});

// Helper to get browser fingerprint
function getFingerprint(req) {
  const fp = req.get('x-client-fingerprint');
  if (fp) return fp;
  const ua = req.headers['user-agent'] || '';
  const ip = req.ip || req.connection.remoteAddress || '';
  return require('crypto').createHash('sha256').update(ua + ip).digest('hex');
}

// ---------- SIGNUP ----------
app.post('/signup', async (req, res) => {
  const { email, password } = req.body;
  const hash = await bcrypt.hash(password, 12);
  try {
    const r = await pool.query(
      `INSERT INTO users(email, password_hash) VALUES ($1,$2) RETURNING id,email`,
      [email, hash]
    );
    req.headers['x-client-fingerprint'] = getFingerprint(req);
    await issueTokens(res, r.rows[0], req);
    res.json({ user: r.rows[0] });
  } catch (e) {
    if (e.code === '23505') return res.status(400).json({ error: 'Email already registered' });
    res.status(400).json({ error: 'Signup failed', detail: e.message });
  }
});

// ---------- LOGIN ----------
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const r = await pool.query(`SELECT id,email,password_hash FROM users WHERE email=$1`, [email]);
  if (!r.rowCount) return res.status(401).json({ error: 'Invalid credentials' });
  const ok = await bcrypt.compare(password, r.rows[0].password_hash);
  if (!ok) return res.status(401).json({ error: 'Invalid credentials' });

  req.headers['x-client-fingerprint'] = getFingerprint(req);
  await issueTokens(res, r.rows[0], req);
  res.json({ user: { id: r.rows[0].id, email } });
});

// ---------- REFRESH ----------
app.post('/refresh', async (req, res) => {
  req.headers['x-client-fingerprint'] = getFingerprint(req);
  try {
    const out = await refreshTokens(req, res);
    if (!res.headersSent && out) res.json(out);
  } catch (e) {
    if (!res.headersSent) {
      res.clearCookie('access_token', { path: '/' });
      res.clearCookie('refresh_token', { path: '/' });
      res.clearCookie('sid', { path: '/' });
      res.status(401).json({ error: 'Refresh failed' });
    }
  }
});

// ---------- LOGOUT ----------
app.post('/api/auth/logout', logout);

// ---------- CHECK ----------
app.get('/api/auth/check', (req, res) => {
  const token = req.cookies?.access_token;
  if (!token) {
    res.clearCookie('access_token', { path: '/' });
    res.clearCookie('refresh_token', { path: '/' });
    res.clearCookie('sid', { path: '/' });
    return res.status(401).json({ error: 'No token' });
  }
  try {
    require('jsonwebtoken').verify(token, process.env.JWT_SECRET);
    res.json({ ok: true });
  } catch {
    res.clearCookie('access_token', { path: '/' });
    res.clearCookie('refresh_token', { path: '/' });
    res.clearCookie('sid', { path: '/' });
    res.status(401).json({ error: 'Expired/invalid token' });
  }
});

// ---------- PROTECTED ROUTE ----------
app.get('/api/protected', authCheck, (req, res) => {  // UPDATED
  res.json({ msg: `Hello user ${req.user.id}` });
});

// ---------- STATIC FRONTEND ----------
const ROOT = path.resolve(__dirname, 'src/');
app.use(express.static(ROOT, {
  maxAge: process.env.NODE_ENV === 'production' ? '7d' : 0,
  etag: true,
  lastModified: true
}));

app.get('/', (_req,res)=> {
  return res.sendFile(path.join(ROOT,'Html_pages','index.html'));
});

app.get('/login', (_req,res)=> {
  return res.sendFile(path.join(ROOT,'Html_pages','login.html'));
});

app.get('/signup', (_req,res)=> {
  return res.sendFile(path.join(ROOT,'Html_pages','signup.html'));
});

app.get('/scanner', (_req,res)=> {
  return res.sendFile(path.join(ROOT,'Html_pages','scanner.html'));
});

app.get('/profile', (_req,res)=> {
  return res.sendFile(path.join(ROOT,'Html_pages','profile.html'));
});

// ---------- CLEANUP ----------
const CLEANUP_INTERVAL_MS = 5 * 60 * 1000;
setInterval(async () => {
  try {
    const refreshMs = ms(process.env.JWT_REFRESH_EXPIRES_IN || "7d");
    const refreshSec = Math.floor(refreshMs / 1000);
    await pool.query(
      `UPDATE refresh_tokens
         SET revoked_at = now()
       WHERE revoked_at IS NULL
         AND created_at < now() - ($1 || ' seconds')::interval`,
      [refreshSec]
    );
  } catch (e) {
    if (process.env.NODE_ENV !== 'production') {
      console.error("Cleanup error:", e.message);
    }
  }
}, CLEANUP_INTERVAL_MS);

// ---------- START ----------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server listening on http://localhost:${PORT}`));
