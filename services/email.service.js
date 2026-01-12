require("dotenv").config();

const nodemailer = require("nodemailer");

const transporter = nodemailer.createTransport({
    host: "smtp.gmail.com",
    port: 587,
    secure: false,
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
    },
});

const sendVerificationEmail = async (email, token) => {
    const verificationLink = `${process.env.BACKEND_URL}/auth/verify-email?token=${token}`;

    const mailOptions = {
        from: `"Auth Service" <${process.env.EMAIL_USER}>`,
        to: email,
        subject: "Verify your email",
        html: `
      <h2>Email Verification</h2>
      <p>Please click the link below to verify your email:</p>
      <a href="${verificationLink}">Verify Email</a> 
      <p>This link will expire in 24 hours.</p>
    `,
    };

    await transporter.sendMail(mailOptions);
};

const sendPasswordResetOtp = async (email, otp) => {
    const mailOptions = {
        from: `"Auth Service" <${process.env.EMAIL_USER}>`,
        to: email,
        subject: "Password Reset OTP",
        html: `
            <div style="font-family: Arial, sans-serif; line-height: 1.6;">
                <h2>Password Reset Request</h2>
                <p>You requested to reset your password.</p>

                <p><strong>Your One-Time Password (OTP):</strong></p>

                <h1 style="letter-spacing: 4px;">${otp}</h1>

                <p>This OTP is valid for <strong>15 minutes</strong>.</p>

                <p>If you did not request a password reset, please ignore this email.</p>

                <p><strong>Do not share this OTP with anyone.</strong></p>

                <br />
                <p>— Auth Service Team</p>
            </div>
        `,
    };

    await transporter.sendMail(mailOptions);
};

module.exports = { sendVerificationEmail, sendPasswordResetOtp };
