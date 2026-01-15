require("dotenv").config();

const bcrypt = require("bcrypt");
const crypto = require("crypto");

const User = require("../models/user.model.js");
const RefreshToken = require("../models/refreshToken.model.js");

const generateEmailVerificationToken = require("../utils/emailVerificationToken.js");
const { generateAccessToken } = require("../utils/accessToken.js");

const {
    generateRefreshToken,
    hashRefreshToken,
} = require("../utils/refreshToken.js");

const { redisClient } = require("../lib/redis.js");
const PasswordReset = require("../models/passwordReset.model.js");

const register = async (req, res) => {
    try {
        const { fullName, email, password } = req.body;

        // 2. Check if user already exists
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(409).json({
                success: false,
                message: "User already exists with this email",
            });
        }

        // 3. Hash password
        const saltRounds = 12;
        const passwordHash = await bcrypt.hash(password, saltRounds);

        // 4. Create user
        const user = await User.create({
            fullName,
            email,
            password: passwordHash,
        });

        const verificationToken = generateEmailVerificationToken(user);
        await user.save({ validateBeforeSave: false });

        // await sendVerificationEmail(user.email, verificationToken);

        // 5. Send response (never send password hash)
        return res.status(201).json({
            success: true,
            message:
                "Registration successful. Please verify your email address to activate your account.",
            verificationLink: `${process.env.BACKEND_URL}/auth/verify-email?token=${verificationToken}`,
        });
    } catch (error) {
        console.error("Register Error:", error);

        return res.status(500).json({
            success: false,
            message: "Internal server error",
        });
    }
};

const verifyEmail = async (req, res) => {
    try {
        const { token } = req.query;

        if (!token) {
            return res.status(400).json({
                success: false,
                message: "Verification token is missing",
            });
        }

        const hashedToken = crypto
            .createHash("sha256")
            .update(token)
            .digest("hex");

        const user = await User.findOne({
            emailVerificationToken: hashedToken,
            emailVerificationExpires: { $gt: Date.now() },
        });

        if (!user) {
            return res.status(400).json({
                success: false,
                message: "Token is invalid or has expired",
            });
        }

        // If already verified (extra safety)
        if (user.isEmailVerified) {
            return res.status(200).json({
                success: true,
                message: "Email is already verified",
            });
        }

        user.isEmailVerified = true;
        user.emailVerificationToken = undefined;
        user.emailVerificationExpires = undefined;

        await user.save();

        return res.status(200).json({
            success: true,
            message: "Email verified successfully. You can now log in.",
        });
    } catch (error) {
        console.error("Email verification error:", error);

        return res.status(500).json({
            success: false,
            message: "Internal server error",
        });
    }
};

const resendVerificationLink = async (req, res) => {
    try {
        const { email } = req.body;

        if (!email) {
            return res.status(400).json({
                success: false,
                message: "Email is required",
            });
        }

        if (await redisClient.get(`email:cooldown:${email}`)) {
            return res.status(429).json({
                success: false,
                message:
                    "An email verification link has already been sent. Please try again after 5 minutes.",
            });
        }

        const user = await User.findOne({ email });

        if (!user) {
            return res.status(404).json({
                success: false,
                message: "Email not found",
            });
        }

        if (user.isEmailVerified) {
            return res.status(200).json({
                success: true,
                message: "Email already verified. You can log in.",
            });
        }

        const verificationToken = generateEmailVerificationToken(user);
        await user.save({ validateBeforeSave: false });

        await redisClient.set(`email:cooldown:${email}`, "1", { EX: 300 });

        return res.status(200).json({
            success: true,
            message:
                "Please verify your email address to activate your account.",
            verificationLink: `${process.env.BACKEND_URL}/auth/verify-email?token=${verificationToken}`,
        });
    } catch (error) {
        console.error("Resend verification link error:", error);

        return res.status(500).json({
            success: false,
            message: "Internal server error",
        });
    }
};

const login = async (req, res) => {
    try {
        const { email, password } = req.body;

        // Validate input
        if (!email || !password) {
            return res.status(400).json({
                success: false,
                message: "Email and password are required",
            });
        }

        // Find user (explicitly select password)
        const user = await User.findOne({ email }).select("+password");

        if (!user) {
            return res.status(401).json({
                success: false,
                message: "Invalid email or password",
            });
        }

        // Compare password
        const isPasswordValid = await bcrypt.compare(password, user.password);

        if (!isPasswordValid) {
            return res.status(401).json({
                success: false,
                message: "Invalid email or password",
            });
        }

        if (!user.isEmailVerified) {
            return res.status(403).json({
                success: false,
                message: "Please verify your email before logging in",
            });
        }

        // Revoke previous refresh tokens (important)
        await RefreshToken.updateMany(
            { user: user._id, revoked: false },
            { revoked: true }
        );

        // Generate Access Token
        const accessToken = generateAccessToken(user);

        // Generate Refresh Token
        const refreshToken = generateRefreshToken();
        const tokenHash = hashRefreshToken(refreshToken);

        await RefreshToken.create({
            user: user._id,
            tokenHash,
            expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days
        });

        // Send cookie to the client
        res.cookie("refreshToken", refreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: "strict",
            path: "/auth",
            maxAge: 7 * 24 * 60 * 60 * 1000,
        });

        // Send response
        return res.status(200).json({
            success: true,
            message: "Login successful",
            accessToken, // Access Token is sent to the client
        });
    } catch (error) {
        console.error("Login error:", error);

        return res.status(500).json({
            success: false,
            message: "Internal server error",
        });
    }
};

const getMe = async (req, res) => {
    try {
        const { userId } = req.auth;

        const user = await User.findById(userId).select("-password -__v");

        if (!user) {
            return res.status(404).json({
                success: false,
                message: "User not found",
            });
        }

        res.status(200).json({
            success: true,
            data: user,
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: "Internal server error",
        });
    }
};

const admin = async (req, res) => {
    return res.status(200).json({
        success: true,
        message: "Welcome!",
    });
};

const refresh = async (req, res) => {
    try {
        const token = req.cookies.refreshToken;

        if (!token)
            return res
                .status(401)
                .json({ success: false, message: "Unauthorized" });

        const tokenHash = hashRefreshToken(token);

        const storedToken = await RefreshToken.findOne({
            tokenHash,
            revoked: false,
            expiresAt: { $gt: new Date() },
        }).populate("user");

        if (!storedToken)
            return res
                .status(403)
                .json({ success: false, message: "Invalid refresh token" });

        // Rotate refresh token
        storedToken.revoked = true;
        await storedToken.save();

        const newRefreshToken = generateRefreshToken();
        const newHash = hashRefreshToken(newRefreshToken);

        await RefreshToken.create({
            user: storedToken.user._id,
            tokenHash: newHash,
            expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
        });

        const accessToken = generateAccessToken(storedToken.user);

        res.cookie("refreshToken", newRefreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: "strict",
            path: "/auth",
            maxAge: 7 * 24 * 60 * 60 * 1000,
        });

        return res.status(200).json({
            success: true,
            accessToken,
        });
    } catch (error) {
        console.error("Refresh token error:", error);

        return res.status(500).json({
            success: false,
            message: "Internal server error",
        });
    }
};

const logout = async (req, res) => {
    try {
        const { jti, exp } = req.auth;

        // calculate remaining lifetime
        const ttl = exp - Math.floor(Date.now() / 1000);

        if (ttl > 0) {
            await redisClient.set(`blacklist:${jti}`, "true", { EX: ttl });
        }

        const token = req.cookies.refreshToken;

        if (token) {
            const tokenHash = hashRefreshToken(token);

            await RefreshToken.updateOne(
                { tokenHash, revoked: false },
                { revoked: true }
            );
        }

        res.clearCookie("refreshToken", { path: "/auth" });

        return res.status(200).json({
            success: true,
            message: "Logged out successfully",
        });
    } catch (error) {
        console.error("Logout error:", error);

        return res.status(500).json({
            success: false,
            message: "Internal server error",
        });
    }
};

const logoutAll = async (req, res) => {
    try {
        const { userId, jti, exp } = req.auth; // from protectRoute middleware

        // calculate remaining lifetime
        const ttl = exp - Math.floor(Date.now() / 1000);

        if (ttl > 0) {
            await redisClient.set(`blacklist:${jti}`, "true", { EX: ttl });
        }

        // Revoke all active refresh tokens for the user
        await RefreshToken.updateMany(
            { user: userId, revoked: false },
            { revoked: true }
        );

        // Clear refresh token cookie on current device
        res.clearCookie("refreshToken", { path: "/auth" });

        return res.status(200).json({
            success: true,
            message: "Logged out from all devices successfully",
        });
    } catch (error) {
        console.error("Logout-all error:", error);

        return res.status(500).json({
            success: false,
            message: "Internal server error",
        });
    }
};

const changePassword = async (req, res) => {
    try {
        const { oldPassword, newPassword } = req.body;
        const { userId, jti, exp } = req.auth;

        // Fetch user with password
        const user = await User.findById(userId).select("+password");
        if (!user) {
            return res.status(404).json({
                success: false,
                message: "User not found",
            });
        }

        // Verify old password
        const isMatch = await bcrypt.compare(oldPassword, user.password);
        if (!isMatch) {
            return res.status(401).json({
                success: false,
                message: "Old password is incorrect",
            });
        }

        // Hash & update password
        const saltRounds = 12;
        user.password = await bcrypt.hash(newPassword, saltRounds);
        await user.save();

        // Revoke ALL refresh tokens (logout from all devices)
        await RefreshToken.updateMany(
            { user: userId, revoked: false },
            { revoked: true }
        );

        // Blacklist CURRENT access token (instant logout)
        const ttl = exp - Math.floor(Date.now() / 1000);
        if (ttl > 0) {
            await redisClient.set(`blacklist:${jti}`, "true", { EX: ttl });
        }

        // Clear refresh token cookie on current device
        res.clearCookie("refreshToken", { path: "/auth" });

        return res.status(200).json({
            success: true,
            message: "Password changed successfully. Please log in again.",
        });
    } catch (error) {
        console.error("Change password error: ", error);

        return res.status(500).json({
            success: false,
            message: "Internal server error",
        });
    }
};

const forgotPassword = async (req, res) => {
    try {
        const { email } = req.body;

        if (!email) {
            return res.status(400).json({
                success: false,
                message: "Please enter a valid email",
            });
        }

        // Cooldown (60s)
        const cooldownKey = `otp:cooldown:${email}`;
        if (await redisClient.get(cooldownKey)) {
            return res.status(429).json({
                success: false,
                message:
                    "An otp has already been sent. Please try again after 1 minute.",
            });
        }

        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({
                success: false,
                message: "Email does not exist",
            });
        }

        const lockKey = `otp:lock:${user._id}`;
        if (await redisClient.get(lockKey)) {
            const seconds = await redisClient.ttl(`otp:attempts:${user._id}`);

            return res.status(429).json({
                success: false,
                message: `Please try to reset password after ${seconds} seconds.`,
            });
        }

        // Generate & hash otp
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        const otpHash = await bcrypt.hash(otp, 10);

        // Replace any existing reset session (very important)
        await PasswordReset.deleteMany({ user: user._id });

        await PasswordReset.create({
            user: user._id,
            otpHash,
            expiresAt: new Date(Date.now() + 15 * 60 * 1000),
        });

        // Redis protections
        await redisClient.set(cooldownKey, "1", { EX: 60 });
        await redisClient.set(`otp:attempts:${user._id}`, 0, { EX: 900 });

        // sendPasswordResetOtp(email, otp);

        return res.status(200).json({
            success: true,
            message: "An OTP has been sent.",
            otp: `Your One-Time Password (OTP): ${otp}`,
        });
    } catch (error) {
        console.error("Forgot password error:", error);

        return res.status(500).json({
            success: false,
            message: "Internal server error",
        });
    }
};

const verifyResetOtp = async (req, res) => {
    try {
        const { email, otp } = req.body;

        if (!email || !otp) {
            return res.status(400).json({
                success: false,
                message: "Invalid email or otp.",
            });
        }

        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({
                success: false,
                message: "Email does not exist.",
            });
        }

        const reset = await PasswordReset.findOne({
            user: user._id,
            verified: false,
            expiresAt: { $gt: new Date() },
        });

        if (!reset) {
            return res.status(400).json({
                success: false,
                message: "OTP expired or invalid",
            });
        }

        // Attempt tracking
        const attemptsKey = `otp:attempts:${user._id}`;
        const lockKey = `otp:lock:${user._id}`;

        const attempts = await redisClient.incr(attemptsKey);

        if (attempts > 5) {
            // Hard lock for 15 minutes
            await redisClient.set(lockKey, "1", { EX: 900 });
            await redisClient.del(`otp:cooldown:${email}`);

            // Cleanup reset session
            await PasswordReset.deleteMany({ user: user._id });

            return res.status(429).json({
                success: false,
                message:
                    "Too many attempts. Please reset password after 15 minutes.",
            });
        }

        const isValid = await bcrypt.compare(otp, reset.otpHash);
        // const isValid = otp === reset.otpHash;
        if (!isValid) {
            return res.status(400).json({
                success: false,
                message: "Invalid OTP",
            });
        }

        reset.verified = true;
        await reset.save();

        return res.status(200).json({
            success: true,
            message: "OTP verified",
        });
    } catch (error) {
        console.error("Verify OTP error:", error);

        return res.status(500).json({
            success: false,
            message: "Internal server error",
        });
    }
};

const resetPassword = async (req, res) => {
    try {
        const { email, newPassword } = req.body;

        const user = await User.findOne({ email }).select("+password");
        if (!user) {
            return res.status(400).json({
                success: false,
                message: "Invalid email or password",
            });
        }

        const reset = await PasswordReset.findOne({
            user: user._id,
            verified: true,
            expiresAt: { $gt: new Date() },
        });

        if (!reset) {
            return res.status(403).json({
                success: false,
                message: "OTP verification required",
            });
        }

        // Update password
        user.password = await bcrypt.hash(newPassword, 12);
        await user.save();

        // Invalidate sessions
        await RefreshToken.updateMany(
            { user: user._id, revoked: false },
            { revoked: true }
        );

        // Cleanup
        await PasswordReset.deleteMany({ user: user._id });
        await redisClient.del(`otp:attempts:${user._id}`);

        return res.status(200).json({
            success: true,
            message: "Password reset successful. Please log in.",
        });
    } catch (error) {
        console.error("Reset password error:", error);

        return res.status(500).json({
            success: false,
            message: "Internal server error",
        });
    }
};

module.exports = {
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
};
