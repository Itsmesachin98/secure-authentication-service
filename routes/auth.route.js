const express = require("express");
const {
    register,
    login,
    verifyEmail,
    getMe,
    refresh,
    logout,
    logoutAll,
    admin,
} = require("../controllers/auth.controller.js");
const protectRoute = require("../middlewares/protectRoutes.js");
const requireRole = require("../middlewares/requireRole.js");
const loginRateLimiter = require("../middlewares/loginRateLimiter.js");
const apiRateLimiter = require("../middlewares/apiRateLimiter.js");

const router = express.Router();

router.get("/me", protectRoute, apiRateLimiter, getMe);
router.get("/verify-email", verifyEmail);
router.get("/refresh", refresh);
router.get("/admin", protectRoute, requireRole("admin"), admin);

router.post("/register", register);
router.post("/login", loginRateLimiter, login);
router.post("/logout", protectRoute, logout);
router.post("/logout-all", protectRoute, logoutAll);

module.exports = router;
