const express = require("express");
const cors = require("cors");
const dotenv = require("dotenv");
const cookieParser = require("cookie-parser");

const authRoute = require("./routes/auth.route");
const connectDB = require("./lib/db");
const { connectRedis } = require("./lib/redis");
const ipRateLimiter = require("./middlewares/ipRateLimiter");

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

app.use(ipRateLimiter);
app.use("/auth", authRoute);

app.listen(3000, () => console.log("Server is running on port 3000"));
