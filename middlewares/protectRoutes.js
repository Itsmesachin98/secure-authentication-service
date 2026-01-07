const { verifyAccessToken } = require("../utils/generateToken.util");

const protectRoute = (req, res, next) => {
    try {
        const authHeader = req.headers.authorization;

        if (!authHeader || !authHeader.startsWith("Bearer ")) {
            return res.status(401).json({
                success: false,
                message: "Authorization token missing",
            });
        }

        const token = authHeader.split(" ")[1];

        const decoded = verifyAccessToken(token);

        // attach auth context
        req.auth = {
            userId: decoded.sub,
            role: decoded.role,
        };

        next();
    } catch (error) {
        return res.status(401).json({
            success: false,
            message: "Invalid or expired access token",
        });
    }
};

module.exports = protectRoute;
