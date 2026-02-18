require("dotenv").config(); // Load .env variables
const mysql = require("mysql2/promise");

if (!process.env.DATABASE_URL) {
  throw new Error("DATABASE_URL is not set in environment variables!");
}

const pool = mysql.createPool(process.env.DATABASE_URL);

module.exports = pool;
