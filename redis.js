const Redis = require("ioredis");

console.log("REDIS_URL VALUE:", process.env.REDIS_URL);

const redis = new Redis(process.env.REDIS_URL);

redis.on("connect", () => {
  console.log("✅ Redis Connected");
});

redis.on("error", (err) => {
  console.error("❌ Redis Error:", err);
});

module.exports = redis;