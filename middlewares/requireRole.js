const requireRole = (requiredRole) => {
    return (req, res, next) => {
        if (!req.auth || !req.auth.role) {
            return res.status(403).json({
                success: false,
                message: "Forbidden",
            });
        }

        if (req.auth.role !== requiredRole) {
            return res.status(403).json({
                success: false,
                message: "Insufficient permissions",
            });
        }

        next();
    };
};

module.exports = requireRole;
