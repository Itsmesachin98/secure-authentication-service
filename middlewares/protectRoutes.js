const { redisClient } = require("../lib/redis");
const { verifyAccessToken } = require("../utils/generateToken.util");

const protectRoute = async (req, res, next) => {
    try {
        const authHeader = req.headers.authorization;

        if (!authHeader || !authHeader.startsWith("Bearer ")) {
            return res.status(401).json({
                success: false,
                message: "Unauthorized",
            });
        }

        const token = authHeader.split(" ")[1];
        const decoded = verifyAccessToken(token);

        if (!decoded?.sub) {
            throw new Error("Invalid token payload");
        }

        // Blacklist check
        const isBlackListed = await redisClient.get(`blacklist:${decoded.jti}`);

        if (isBlackListed) {
            return res.status(401).json({
                success: false,
                message: "Unauthorized",
            });
        }

        // attach auth context
        req.auth = Object.freeze({
            userId: decoded.sub,
            role: decoded.role,
            jti: decoded.jti,
            exp: decoded.exp,
        });

        next();
    } catch (error) {
        return res.status(401).json({
            success: false,
            message: "Unauthorized",
        });
    }
};

module.exports = protectRoute;
