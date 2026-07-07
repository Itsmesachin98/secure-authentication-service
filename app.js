const dotenv = require("dotenv");
dotenv.config();

const express = require("express");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const swaggerUi = require("swagger-ui-express");

const authRoute = require("./routes/auth.route");
const connectDB = require("./lib/db");
const { connectRedis } = require("./lib/redis");
const ipRateLimiter = require("./middlewares/ipRateLimiter");
const swaggerSpec = require("./docs/swagger");

const PORT = process.env.PORT || 3000;

const app = express();

app.use(cookieParser());
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use("/docs", swaggerUi.serve, swaggerUi.setup(swaggerSpec));

app.use(ipRateLimiter);
app.use("/auth", authRoute);

async function startServer() {
    try {
        await connectDB();
        await connectRedis();

        app.listen(PORT, () => {
            console.log(`Server is running on port ${PORT}`);
        });
    } catch (err) {
        console.error("Failed to start server:", err);
        process.exit(1);
    }
}

startServer();
