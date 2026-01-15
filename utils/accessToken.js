require("dotenv").config();

const jwt = require("jsonwebtoken");
const { v4: uuidv4 } = require("uuid");

const generateAccessToken = (user) => {
    const payload = {
        sub: user._id.toString(),
        role: user.role,
        jti: uuidv4(), // 👈 unique token id
    };

    const options = {
        expiresIn: process.env.JWT_ACCESS_EXPIRES_IN,
        issuer: "secure-auth-service",
        audience: "secure-auth-client",
    };

    return jwt.sign(payload, process.env.JWT_ACCESS_SECRET, options);
};

const verifyAccessToken = (token) => {
    return jwt.verify(token, process.env.JWT_ACCESS_SECRET, {
        issuer: "secure-auth-service",
        audience: "secure-auth-client",
    });
};

module.exports = { generateAccessToken, verifyAccessToken };
