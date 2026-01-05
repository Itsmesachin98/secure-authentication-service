const bcrypt = require("bcrypt");
const User = require("../models/user.model.js");

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

        // 5. Send response (never send password hash)
        return res.status(201).json({
            success: true,
            message: "User registered successfully",
            user: {
                id: user._id,
                fullName: user.fullName,
                email: user.email,
                createdAt: user.createdAt,
            },
        });
    } catch (error) {
        console.error("Register Error:", error);

        return res.status(500).json({
            success: false,
            message: "Internal server error",
        });
    }
};

module.exports = { register };
