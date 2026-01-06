const crypto = require("crypto");

const generateEmailVerificationToken = (user) => {
    const token = crypto.randomBytes(32).toString("hex");

    user.emailVerificationToken = crypto
        .createHash("sha256")
        .update(token)
        .digest("hex");

    user.emailVerificationExpires = Date.now() + 24 * 60 * 60 * 1000; // 24h

    return token;
};

module.exports = generateEmailVerificationToken;
