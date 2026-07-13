const { createClient } = require("redis");

const isDevelopment = process.env.NODE_ENV === "development";

const redisUrl =
    process.env.NODE_ENV === "development"
        ? "redis://redis:6379"
        : process.env.REDIS_URL;

const redisClient = createClient({
    url: redisUrl,
});

redisClient.on("error", (err) => console.error("Redis error:", err));

const connectRedis = async () => {
    await redisClient.connect();

    if (isDevelopment) console.log("Connected to local Redis");
    else console.log("Connected to cloud Redis");
};

module.exports = { redisClient, connectRedis };
