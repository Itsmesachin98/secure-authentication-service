const express = require("express");
const {
    register,
    login,
    verifyEmail,
    getMe,
} = require("../controllers/auth.controller.js");
const requireAuth = require("../middlewares/requireAuth.js");

const router = express.Router();

router.get("/me", requireAuth, getMe);
router.get("/verify-email", verifyEmail);

router.post("/register", register);
router.post("/login", login);

module.exports = router;
