const Joi = require("joi");

// Register validator
const registerSchema = Joi.object({
    fullName: Joi.string()
        .trim()
        .min(3)
        .max(50)
        .pattern(/^[A-Za-z ]+$/)
        .required()
        .messages({
            "string.empty": "Full name is required",
            "string.min": "Full name must be at least 3 characters",
            "string.max": "Full name must be at most 50 characters",
            "string.pattern.base":
                "Full name must contain only alphabets and spaces",
        }),

    email: Joi.string().trim().email().required().messages({
        "string.empty": "Email is required",
        "string.email": "Email must be valid",
    }),

    password: Joi.string()
        .min(8)
        .max(64)
        .required()
        .pattern(
            new RegExp("^(?=.*[A-Z])(?=.*[a-z])(?=.*\\d)(?=.*[^A-Za-z0-9]).+$")
        )
        .messages({
            "string.empty": "Password is required",
            "string.min": "Password must be at least 8 characters",
            "string.pattern.base":
                "Password must contain uppercase, lowercase, number, and special character",
        }),
});

// Change password validator
const changePasswordSchema = Joi.object({
    oldPassword: Joi.string().required().messages({
        "string.empty": "Old password is required",
    }),

    newPassword: Joi.string()
        .min(8)
        .max(64)
        .required()
        .pattern(
            new RegExp("^(?=.*[A-Z])(?=.*[a-z])(?=.*\\d)(?=.*[^A-Za-z0-9]).+$")
        )
        .invalid(Joi.ref("oldPassword")) // must be different
        .messages({
            "string.empty": "New password is required",
            "string.min": "New password must be at least 8 characters",
            "string.pattern.base":
                "New password must contain uppercase, lowercase, number, and special character",
            "any.invalid": "New password must be different from old password",
        }),

    confirmPassword: Joi.string()
        .valid(Joi.ref("newPassword"))
        .required()
        .messages({
            "any.only": "Confirm password must match new password",
            "string.empty": "Confirm password is required",
        }),
});

// Reset password validator
const resetPasswordSchema = Joi.object({
    email: Joi.string().trim().email().required().messages({
        "string.empty": "Email is required",
        "string.email": "Email must be valid",
    }),

    newPassword: Joi.string()
        .min(8)
        .max(64)
        .required()
        .pattern(
            new RegExp("^(?=.*[A-Z])(?=.*[a-z])(?=.*\\d)(?=.*[^A-Za-z0-9]).+$")
        )
        .messages({
            "string.empty": "New password is required",
            "string.min": "New password must be at least 8 characters",
            "string.pattern.base":
                "New password must contain uppercase, lowercase, number, and special character",
        }),

    confirmPassword: Joi.string()
        .valid(Joi.ref("newPassword"))
        .required()
        .messages({
            "any.only": "Confirm password must match new password",
            "string.empty": "Confirm password is required",
        }),
});

module.exports = { registerSchema, changePasswordSchema, resetPasswordSchema };
