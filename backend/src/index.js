import express from "express";
import dotenv from "dotenv";
import cookieParser from "cookie-parser";
import cors from "cors";

import path from "path";

import { connectDB } from "./lib/db.js";

import authRoutes from "./routes/auth.route.js";
import messageRoutes from "./routes/message.route.js";
import { app, server } from "./lib/socket.js";

dotenv.config();

const PORT = process.env.PORT;
const __dirname = path.resolve();

app.use(express.json());
app.use(cookieParser());
app.use(
  cors({
    origin: "http://localhost:5173",
    credentials: true,
  })
);

app.use("/api/auth", authRoutes);
app.use("/api/messages", messageRoutes);

if (process.env.NODE_ENV === "production") {
  app.use(express.static(path.join(__dirname, "../frontend/dist")));

  try {
  app.get('*', (req, res) => {
    console.log("Wildcard route hit:", req.originalUrl);
    res.sendFile(path.resolve(__dirname, '../frontend/dist', 'index.html'));
  });
} catch (err) {
  console.error("⚠️ Error in wildcard route:", err);
}

}

server.listen(PORT, () => {
  console.log("server is running on PORT:" + PORT);
  connectDB();
});