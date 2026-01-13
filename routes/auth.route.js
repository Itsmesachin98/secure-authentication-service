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
    changePassword,
    forgotPassword,
    verifyResetOtp,
    resetPassword,
} = require("../controllers/auth.controller.js");

const protectRoute = require("../middlewares/protectRoutes.js");
const requireRole = require("../middlewares/requireRole.js");
const loginRateLimiter = require("../middlewares/loginRateLimiter.js");
const apiRateLimiter = require("../middlewares/apiRateLimiter.js");
const validateRequest = require("../middlewares/validateRequest.js");

const {
    registerSchema,
    changePasswordSchema,
    resetPasswordSchema,
} = require("../validators/auth.validator.js");

const router = express.Router();

router.get("/me", protectRoute, apiRateLimiter, getMe);
router.get("/verify-email", verifyEmail);
router.get("/refresh", refresh);
router.get("/admin", protectRoute, requireRole("admin"), admin);

router.post("/register", validateRequest(registerSchema), register);
router.post("/login", loginRateLimiter, login);
router.post("/logout", protectRoute, logout);
router.post("/logout-all", protectRoute, logoutAll);

router.post(
    "/change-password",
    protectRoute,
    validateRequest(changePasswordSchema),
    changePassword
);

router.post("/forgot-password", forgotPassword);
router.post("/verify-reset-otp", verifyResetOtp);

router.post(
    "/reset-password",
    validateRequest(resetPasswordSchema),
    resetPassword
);

module.exports = router;
