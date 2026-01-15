const swaggerJSDoc = require("swagger-jsdoc");

const swaggerSpec = swaggerJSDoc({
    definition: {
        openapi: "3.0.0",
        info: {
            title: "Secure Authentication Service",
            version: "1.0.0",
            description:
                "Backend-only authentication service with JWT, refresh token rotation, OTP password reset, Redis rate limiting, Redis blacklist, and RBAC.",
        },
        servers: [
            {
                url: process.env.BACKEND_URL,
                description:
                    process.env.NODE_ENV === "production"
                        ? "Production"
                        : "Development",
            },
        ],
        components: {
            securitySchemes: {
                bearerAuth: {
                    type: "http",
                    scheme: "bearer",
                    bearerFormat: "JWT",
                },
            },
        },
    },
    apis: ["./routes/*.js"], // adjust path
});

module.exports = swaggerSpec;
