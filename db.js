require("dotenv").config();
const { Pool } = require("pg");

console.log("🚨 DATABASE_URL:", process.env.DATABASE_URL);

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

// ✅ FORCE CONNECTION AT START
pool.connect()
  .then(() => console.log("✅ PostgreSQL connected"))
  .catch((err) => console.error("❌ PostgreSQL connection error:", err));

module.exports = {
  query: (text, params) => pool.query(text, params),
  pool,
};