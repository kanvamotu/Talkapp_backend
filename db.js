require("dotenv").config();
const mysql = require("mysql2/promise");

const dbUrl = process.env.DATABASE_URL || process.env.MYSQL_URL;

if (!dbUrl) {
  console.error("Available ENV keys:", Object.keys(process.env));
  throw new Error("No database URL found!");
}

const pool = mysql.createPool(dbUrl);

module.exports = pool;