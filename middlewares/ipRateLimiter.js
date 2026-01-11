const rateLimit = require("../utils/rateLimiter");

const ipRateLimiter = async (req, res, next) => {
    try {
        const ipKey = req.ip;

        const key = `ip:${ipKey}`;
        const allowed = await rateLimit(key, 200, 60);

        if (!allowed) {
            return res.status(429).json({
                success: false,
                message: "Too many requests",
            });
        }

        next();
    } catch (error) {
        // Allow traffic if Redis fails
        console.error("IP rate limiter error:", err);
        next();
    }
};

module.exports = ipRateLimiter;
