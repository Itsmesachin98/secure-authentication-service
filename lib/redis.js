const { createClient } = require("redis");

const redisClient = createClient({
    url: process.env.REDIS_URL,
});

redisClient.on("connect", () => console.log("Redis connecting..."));
redisClient.on("ready", () => console.log("Redis connected and ready"));
redisClient.on("error", (err) => console.error("Redis error:", err));
redisClient.on("end", () => console.log("Redis connection closed"));

const connectRedis = async () => {
    if (!redisClient.isOpen) {
        await redisClient.connect();
    }
};

module.exports = { redisClient, connectRedis };
