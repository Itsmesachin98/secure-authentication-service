const express = require("express");
const cors = require("cors");
const dotenv = require("dotenv");
const cookieParser = require("cookie-parser");
const swaggerUi = require("swagger-ui-express");

const authRoute = require("./routes/auth.route");
const connectDB = require("./lib/db");
const { connectRedis } = require("./lib/redis");
const ipRateLimiter = require("./middlewares/ipRateLimiter");
const swaggerSpec = require("./docs/swagger");

const PORT = process.env.PORT || 3000;

dotenv.config();

connectDB();

const app = express();

(async () => {
    try {
        await connectRedis();
    } catch (err) {
        console.error("Redis failed to connect", err);
        process.exit(1);
    }
})();

app.use(cookieParser());
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use("/docs", swaggerUi.serve, swaggerUi.setup(swaggerSpec));

app.use(ipRateLimiter);
app.use("/auth", authRoute);

app.listen(PORT, () => console.log("Server is running on port 3000"));
