const rateLimit = require("../utils/rateLimiter");

const apiRateLimiter = async (req, res, next) => {
    try {
        const userId = req.auth.userId;

        const key = `api:user:${userId}`;
        const allowed = await rateLimit(key, 100, 60);

        if (!allowed) {
            return res.status(429).json({
                success: false,
                message: "Too many requests. Slow down.",
            });
        }

        next();
    } catch (error) {
        // Redis failed → allow request
        console.error("API rate limiter error:", err);
        next();
    }
};

module.exports = apiRateLimiter;
