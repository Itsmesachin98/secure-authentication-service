const mongoose = require("mongoose");

const userSchema = new mongoose.Schema(
    {
        fullName: {
            type: String,
            required: true,
            trim: true,
            minlength: 2,
            maxlength: 100,
        },

        email: {
            type: String,
            required: true,
            lowercase: true,
            trim: true,
        },

        password: {
            type: String,
            required: true,
            select: false, // never return password hash by default
        },

        role: {
            type: String,
            enum: ["user", "admin"],
            default: "user",
        },

        isEmailVerified: {
            type: Boolean,
            default: false,
        },

        emailVerificationToken: {
            type: String,
            select: false,
        },

        emailVerificationExpires: {
            type: Date,
            select: false,
        },
    },
    {
        timestamps: true, // creates createdAt & updatedAt automatically
        versionKey: false,
    }
);

// Ensure email uniqueness at DB level
userSchema.index(
    { email: 1 },
    { unique: true, collation: { locale: "en", strength: 2 } }
);

const User = mongoose.model("User", userSchema);

module.exports = User;
