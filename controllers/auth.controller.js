const bcrypt = require("bcrypt");
const crypto = require("crypto");

const User = require("../models/user.model.js");
const generateEmailVerificationToken = require("../utils/token.util.js");
const sendVerificationEmail = require("../services/email.service.js");
const { generateAccessToken } = require("../utils/generateToken.util.js");

const register = async (req, res) => {
    try {
        const { fullName, email, password } = req.body;

        // 1. Basic validation
        if (!fullName || !email || !password) {
            return res.status(400).json({
                success: false,
                message: "All fields are required",
            });
        }

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

        await sendVerificationEmail(user.email, verificationToken);

        // 5. Send response (never send password hash)
        return res.status(201).json({
            success: true,
            message:
                "Registration successful. Please verify your email address to activate your account.",
        });
    } catch (error) {
        console.error("Register Error:", error);

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

        const accessToken = generateAccessToken(user);
        console.log("This is the access token: ", accessToken);

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

module.exports = { register, login, verifyEmail, getMe };
