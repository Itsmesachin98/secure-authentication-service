const express = require("express");
const {
    register,
    login,
    verifyEmail,
    getMe,
    refresh,
    logout,
    logoutAll,
} = require("../controllers/auth.controller.js");
const protectRoute = require("../middlewares/protectRoutes.js");

const router = express.Router();

router.get("/me", protectRoute, getMe);
router.get("/verify-email", verifyEmail);
router.get("/refresh", refresh);

router.post("/register", register);
router.post("/login", login);
router.post("/logout", logout);
router.post("/logout-all", protectRoute, logoutAll);

module.exports = router;
