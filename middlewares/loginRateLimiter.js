const rateLimit = require("../utils/rateLimiter");

const loginRateLimiter = async (req, res, next) => {
    try {
        const ip = req.ip;
        const email = req.body.email;

        const ipKey = `login:ip:${ip}`;
        const emailKey = `login:email:${email}`;

        const ipAllowed = await rateLimit(ipKey, 5, 600);
        const emailAllowed = await rateLimit(emailKey, 5, 600);

        if (!ipAllowed || !emailAllowed) {
            return res.status(429).json({
                success: false,
                message: "Too many login attempts. Try again later.",
            });
        }

        next();
    } catch (error) {
        // Redis failed → block login (secure default)
        console.error("Login rate limiter error:", err);

        return res.status(429).json({
            success: false,
            message: "Login temporarily unavailable",
        });
    }
};

module.exports = loginRateLimiter;
