const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(cors());
app.use(express.json()); // To read JSON from forms

// Serve your static files (HTML, CSS, JS) from the "public" folder
app.use(express.static("public"));

// --- MongoDB Connection ---
mongoose
  .connect(process.env.MONGODB_URI, {
    family: 4, // Forces IPv4, bypasses IPv6 DNS issues
  })
  .then(() => console.log("✅ Connected to MongoDB Atlas"))
  .catch((err) => console.log("❌ MongoDB Error:", err));

// --- Mongoose Schemas (Database Structure) ---

// 1. User Schema
const UserSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
});
const User = mongoose.model("User", UserSchema);

// 2. Message Schema (for Contact form)
const MessageSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true },
  message: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
});
const Message = mongoose.model("Message", MessageSchema);

// --- Helper: JWT Authentication Middleware ---
const authenticate = (req, res, next) => {
  const token = req.headers["authorization"];
  if (!token)
    return res.status(401).json({ error: "Access denied. No token provided." });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).json({ error: "Invalid or expired token." });
  }
};

// --- API ROUTES ---

// 1. REGISTER
app.post("/api/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    // Check if user exists
    const existingUser = await User.findOne({ email });
    if (existingUser)
      return res.status(400).json({ error: "Email already registered." });

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({ name, email, password: hashedPassword });
    await newUser.save();

    res.status(201).json({ message: "Registration successful! Please login." });
  } catch (error) {
    res.status(500).json({ error: "Server error during registration." });
  }
});

// 2. LOGIN
app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user)
      return res.status(400).json({ error: "Invalid email or password." });

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword)
      return res.status(400).json({ error: "Invalid email or password." });

    // Generate JWT Token
    const token = jwt.sign(
      { id: user._id, name: user.name, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.json({
      message: "Login successful!",
      token,
      user: { name: user.name, email: user.email },
    });
  } catch (error) {
    res.status(500).json({ error: "Server error during login." });
  }
});

// 3. CONTACT (Submit Message)
app.post("/api/contact", async (req, res) => {
  try {
    const { name, email, message } = req.body;
    const newMessage = new Message({ name, email, message });
    await newMessage.save();
    res.status(201).json({ message: "Message sent successfully!" });
  } catch (error) {
    res.status(500).json({ error: "Failed to send message." });
  }
});

// 4. ADMIN - Get all messages (Protected)
app.get("/api/admin/messages", authenticate, async (req, res) => {
  try {
    const messages = await Message.find().sort({ createdAt: -1 });
    res.json(messages);
  } catch (error) {
    res.status(500).json({ error: "Failed to fetch messages." });
  }
});

// --- START SERVER ---
app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
});
