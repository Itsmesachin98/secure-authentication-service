const mongoose = require("mongoose");

const passwordResetSchema = new mongoose.Schema(
    {
        user: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "User",
            required: true,
            index: true,
        },

        otpHash: {
            type: String,
            required: true,
        },

        expiresAt: {
            type: Date,
            required: true,
            index: true,
        },

        verified: {
            type: Boolean,
            default: false,
        },
    },
    { timestamps: true }
);

const PasswordReset = mongoose.model("PasswordReset", passwordResetSchema);

module.exports = PasswordReset;
