// middleware/authCheck.js
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

function hash(str) {
  return crypto.createHash('sha256').update(str).digest('hex');
}

module.exports = function authCheck(req, res, next) {
  const token = req.cookies['access_token'];
  if (!token) return res.status(401).json({ error: 'No token' });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    // Compare UA + FP
    const ua = req.headers['user-agent'] || '';
    const fp = req.headers['x-client-fingerprint'] || '';
    if (decoded.ua !== hash(ua) || decoded.fp !== hash(fp)) {
      return res.status(401).json({ error: 'Token context mismatch' });
    }

    req.user = { id: decoded.uid, sid: decoded.sid };
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid token' });
  }
};
