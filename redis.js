const redis = require("redis");

const redisClient = redis.createClient({
  url: "redis://127.0.0.1:6379",
});

redisClient.on("error", (err) => {
  console.error("❌ Redis Error:", err);
});

redisClient.on("connect", () => {
  console.log("✅ Redis connected");
});

redisClient.connect();

module.exports = redisClient;
