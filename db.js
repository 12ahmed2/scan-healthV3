// db.js (same folder as server.js or adjust path)
require('dotenv').config();
const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,              // e.g. postgresql://postgres:pass@127.0.0.1:5050/scan_health
  ssl: process.env.PGSSL === 'require' ? { rejectUnauthorized: false } : false,
});

module.exports = pool;