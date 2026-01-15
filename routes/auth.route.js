/**
 * @swagger
 * tags:
 *   name: Auth
 *   description: Secure Authentication APIs (JWT + Refresh Rotation + OTP Reset + RBAC)
 */

const express = require("express");

const {
    register,
    verifyEmail,
    resendVerificationLink,
    login,
    getMe,
    admin,
    refresh,
    logout,
    logoutAll,
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

/**
 * @swagger
 * /auth/register:
 *   post:
 *     summary: Register a new user
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [fullName, email, password]
 *             properties:
 *               fullName:
 *                 type: string
 *                 example: "Your Name"
 *               email:
 *                 type: string
 *                 example: "youremail@gmail.com"
 *               password:
 *                 type: string
 *                 example: "StrongPassword"
 *     responses:
 *       201:
 *         description: Registered successfully
 *       400:
 *         description: Validation error
 */
router.post("/register", validateRequest(registerSchema), register);

/**
 * @swagger
 * /auth/verify-email:
 *   get:
 *     summary: Verify email using token
 *     tags: [Auth]
 *     parameters:
 *       - in: query
 *         name: token
 *         required: true
 *         schema:
 *           type: string
 *         example: "abc123token"
 *     responses:
 *       200:
 *         description: Email verified successfully
 *       400:
 *         description: Invalid or expired token
 */
router.get("/verify-email", verifyEmail);

router.post("/resend-verificaton-link", resendVerificationLink);

/**
 * @swagger
 * /auth/login:
 *   post:
 *     summary: Login (returns access token + sets refresh token cookie)
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [email, password]
 *             properties:
 *               email:
 *                 type: string
 *                 example: "sachin@gmail.com"
 *               password:
 *                 type: string
 *                 example: "Strong@123"
 *     responses:
 *       200:
 *         description: Login successful
 *       401:
 *         description: Invalid credentials
 *       429:
 *         description: Too many attempts (rate limited)
 */
router.post("/login", loginRateLimiter, login);

/**
 * @swagger
 * /auth/me:
 *   get:
 *     summary: Get logged-in user details (Protected)
 *     tags: [Auth]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: User details returned
 *       401:
 *         description: Unauthorized
 */
router.get("/me", protectRoute, apiRateLimiter, getMe);

/**
 * @swagger
 * /auth/admin:
 *   get:
 *     summary: Admin protected route (RBAC)
 *     tags: [Auth]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Admin route accessed successfully
 *       403:
 *         description: Insufficient permissions
 *       401:
 *         description: Unauthorized
 */
router.get("/admin", protectRoute, requireRole("admin"), admin);

/**
 * @swagger
 * /auth/refresh:
 *   get:
 *     summary: Refresh access token (Refresh token rotation)
 *     tags: [Auth]
 *     responses:
 *       200:
 *         description: New access token issued
 *       403:
 *         description: Invalid refresh token
 */
router.get("/refresh", refresh);

/**
 * @swagger
 * /auth/logout:
 *   post:
 *     summary: Logout current session (revoke refresh token + blacklist access token)
 *     tags: [Auth]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Logged out successfully
 *       401:
 *         description: Unauthorized
 */
router.post("/logout", protectRoute, logout);

/**
 * @swagger
 * /auth/logout-all:
 *   post:
 *     summary: Logout from all devices (revoke all refresh tokens)
 *     tags: [Auth]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Logged out from all devices successfully
 *       401:
 *         description: Unauthorized
 */
router.post("/logout-all", protectRoute, logoutAll);

/**
 * @swagger
 * /auth/change-password:
 *   post:
 *     summary: Change password (Protected)
 *     tags: [Auth]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [oldPassword, newPassword, confirmPassword]
 *             properties:
 *               oldPassword:
 *                 type: string
 *                 example: "Strong@123"
 *               newPassword:
 *                 type: string
 *                 example: "NewStrong@123"
 *               confirmPassword:
 *                 type: string
 *                 example: "NewStrong@123"
 *     responses:
 *       200:
 *         description: Password changed successfully
 *       401:
 *         description: Unauthorized / Old password incorrect
 */
router.post(
    "/change-password",
    protectRoute,
    validateRequest(changePasswordSchema),
    changePassword
);

/**
 * @swagger
 * /auth/forgot-password:
 *   post:
 *     summary: Request OTP for password reset (generic response)
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [email]
 *             properties:
 *               email:
 *                 type: string
 *                 example: "sachin@gmail.com"
 *     responses:
 *       200:
 *         description: OTP sent (generic response)
 */
router.post("/forgot-password", forgotPassword);

/**
 * @swagger
 * /auth/verify-reset-otp:
 *   post:
 *     summary: Verify OTP for password reset
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [email, otp]
 *             properties:
 *               email:
 *                 type: string
 *                 example: "sachin@gmail.com"
 *               otp:
 *                 type: string
 *                 example: "123456"
 *     responses:
 *       200:
 *         description: OTP verified
 *       400:
 *         description: Invalid OTP
 *       429:
 *         description: Too many attempts
 */
router.post("/verify-reset-otp", verifyResetOtp);

/**
 * @swagger
 * /auth/reset-password:
 *   post:
 *     summary: Reset password after OTP verification
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [email, newPassword, confirmPassword]
 *             properties:
 *               email:
 *                 type: string
 *                 example: "sachin@gmail.com"
 *               newPassword:
 *                 type: string
 *                 example: "Reset@12345"
 *               confirmPassword:
 *                 type: string
 *                 example: "Reset@12345"
 *     responses:
 *       200:
 *         description: Password reset successful
 *       403:
 *         description: OTP verification required
 */
router.post(
    "/reset-password",
    validateRequest(resetPasswordSchema),
    resetPassword
);

module.exports = router;
