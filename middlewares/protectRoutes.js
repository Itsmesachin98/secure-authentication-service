const { verifyAccessToken } = require("../utils/generateToken.util");

const protectRoute = (req, res, next) => {
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

        // attach auth context
        req.auth = Object.freeze({
            userId: decoded.sub,
            role: decoded.role,
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
