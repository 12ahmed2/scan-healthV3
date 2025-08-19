// auth.js
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const pool = require('./db.js');
const { v4: uuidv4 } = require('uuid');
const ms = require('ms');

const ACCESS_SECRET  = process.env.JWT_SECRET;
const REFRESH_SECRET = process.env.JWT_REFRESH_SECRET;

const ACCESS_TTL     = process.env.JWT_EXPIRES_IN || '15m';
const REFRESH_TTL    = process.env.JWT_REFRESH_EXPIRES_IN || '7d';

const ACCESS_MS  = ms(ACCESS_TTL);
const REFRESH_MS = ms(REFRESH_TTL);

const hash = s => crypto.createHash('sha256').update(String(s)).digest('hex');
const uaHashOf = req => hash(req.get('user-agent') || '');

// 🚨 require fingerprint header explicitly, fallback if missing
const fpHashOf = req => {
  let raw = req.get('x-client-fingerprint');
  if (!raw) {
    // fallback: use user-agent + IP + random salt
    const ua = req.get('user-agent') || '';
    const ip = req.ip || req.connection?.remoteAddress || '';
    raw = ua + ip;
  }
  return hash(raw);
};

// cookies
function setAuthCookies(res, access, refresh, sid) {
  const isProd = process.env.NODE_ENV === 'production';
  const common = { httpOnly: true, sameSite: 'Strict', path: '/', secure: isProd };
  res.cookie('access_token',  access,  { ...common, maxAge: ACCESS_MS });
  res.cookie('refresh_token', refresh, { ...common, maxAge: REFRESH_MS });
  res.cookie('sid',           sid,     { ...common, maxAge: REFRESH_MS });
}
function clearAuthCookies(res) {
  res.clearCookie('access_token',  { path: '/' });
  res.clearCookie('refresh_token', { path: '/' });
  res.clearCookie('sid',           { path: '/' });
}

// sign
function signAccess(user, sid, uaH, fpH) {
  return jwt.sign({ sub: user.id, email: user.email ?? null, jti: uuidv4(), sid, ua: uaH, fp: fpH }, ACCESS_SECRET, { expiresIn: ACCESS_TTL });
}
function signRefresh(user, sid, uaH, fpH) {
  return jwt.sign({ sub: user.id, sid, ua: uaH, fp: fpH }, REFRESH_SECRET, { expiresIn: REFRESH_TTL });
}

/* issue tokens */
async function issueTokens(res, user, req) {
  const sid = uuidv4();
  const uaH = uaHashOf(req);
  const fpH = fpHashOf(req);
  if (!fpH) {
    return res.status(400).json({ error: 'Missing fingerprint' });
  }

  const access  = signAccess(user, sid, uaH, fpH);
  const refresh = signRefresh(user, sid, uaH, fpH);

  // Save refresh token with correct columns
  await pool.query(
    `INSERT INTO refresh_tokens(user_id, token, session_id, ua_hash, fp_hash, created_at)
     VALUES ($1,$2,$3,$4,$5,now())`,
    [user.id, hash(refresh), sid, uaH, fpH]
  );

  setAuthCookies(res, access, refresh, sid);
  return { access, refresh, sid };
}

/* middleware */
function requireAuth(req, res, next) {
  const token =
    req.cookies?.access_token ||
    (req.headers.authorization || '').replace('Bearer ', '');
  if (!token) {
    clearAuthCookies(res);
    return res.status(401).json({ error: 'No token' });
  }

  try {
    const payload = jwt.verify(token, ACCESS_SECRET);
    const sidCookie = req.cookies?.sid;
    const uaH = uaHashOf(req);
    const fpH = fpHashOf(req);

    if (!sidCookie || !fpH ||
        sidCookie !== payload.sid ||
        uaH !== payload.ua ||
        fpH !== payload.fp) {
      clearAuthCookies(res);
      return res.status(401).json({ error: 'Token context mismatch' });
    }

    req.user = payload;
    // Optionally check fingerprint here if session-based
    return next();
  } catch {
    clearAuthCookies(res);
    return res.status(401).json({ error: 'Invalid or expired access token' });
  }
}

/* refresh */
async function refreshTokens(req, res) {
  const rt = req.cookies?.refresh_token;
  const sidCookie = req.cookies?.sid;
  if (!rt || !sidCookie) {
    clearAuthCookies(res);
    return res.status(401).json({ error: 'No refresh token' });
  }

  let payload;
  try {
    payload = jwt.verify(rt, REFRESH_SECRET);
  } catch (err) {
    try {
      const dec = jwt.decode(rt);
      if (dec?.sub) {
        await pool.query(
          `UPDATE refresh_tokens SET revoked_at = now()
           WHERE user_id=$1 AND token=$2 AND revoked_at IS NULL`,
          [dec.sub, hash(rt)]
        );
      }
    } catch {}
    clearAuthCookies(res);
    return res.status(401).json({ error: 'Expired/invalid refresh token' });
  }

  const uaH = uaHashOf(req);
  const fpH = fpHashOf(req);
  if (!fpH ||
      payload.sid !== sidCookie ||
      payload.ua !== uaH ||
      payload.fp !== fpH) {
    clearAuthCookies(res);
    return res.status(401).json({ error: 'Refresh context mismatch' });
  }

  // Get refresh token from DB using correct column
  const r = await pool.query(
    `SELECT * FROM refresh_tokens WHERE token=$1 AND revoked_at IS NULL`,
    [hash(rt)]
  );
  if (!r.rowCount) {
    clearAuthCookies(res);
    return res.status(401).json({ error: 'Refresh not found or revoked' });
  }

  // Check fingerprint
  if (r.rows[0].fp_hash !== fpH) {
    // Invalidate token
    await pool.query(
      `UPDATE refresh_tokens SET revoked_at=now() WHERE token=$1`,
      [hash(rt)]
    );
    clearAuthCookies(res);
    return res.status(401).json({ error: 'Fingerprint mismatch' });
  }

  // rotate
  await pool.query(`UPDATE refresh_tokens SET revoked_at=now() WHERE token=$1`, [hash(rt)]);
  const user = { id: payload.sub, email: null };
  const access  = signAccess(user, payload.sid, uaH, fpH);
  const refresh = signRefresh(user, payload.sid, uaH, fpH);

  await pool.query(
    `INSERT INTO refresh_tokens (user_id, token, session_id, ua_hash, fp_hash, created_at)
       VALUES ($1,$2,$3,$4,$5,now())`,
    [user.id, hash(refresh), payload.sid, uaH, fpH]
  );

  setAuthCookies(res, access, refresh, payload.sid);
  return { ok: true };
}

/* logout */
async function logout(req, res) {
  const rt  = req.cookies?.refresh_token;
  const sid = req.cookies?.sid;
  if (rt && sid) {
    await pool.query(
      `UPDATE refresh_tokens SET revoked_at=now()
       WHERE token=$1 OR session_id=$2`,
      [hash(rt), sid]
    );
  }
  clearAuthCookies(res);
  return res.json({ ok: true });
}

module.exports = {
  issueTokens, requireAuth, refreshTokens, logout,
  setAuthCookies, clearAuthCookies, signAccess, signRefresh
};
