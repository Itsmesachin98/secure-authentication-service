const { redisClient } = require("../lib/redis");

const rateLimit = async (key, limit, windowInSeconds) => {
    const current = await redisClient.incr(key);

    if (current === 1) {
        await redisClient.expire(key, windowInSeconds);
    }

    return current <= limit;
};

module.exports = rateLimit;
