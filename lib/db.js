const mongoose = require("mongoose");

const connectDB = async () => {
    try {
        const uri =
            process.env.NODE_ENV === "development"
                ? "mongodb://mongodb:27017/SecureAuth"
                : process.env.MONGODB_URI;

        const conn = await mongoose.connect(uri);
        console.log(`MongoDB connected: ${conn.connection.host}`);
    } catch (error) {
        console.log("MongoDB connection error", error);
        process.exit(1);
    }
};

module.exports = connectDB;
