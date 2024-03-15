const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const createError = require("http-errors");
const z = require("zod");
require("dotenv").config();

const app = express();
const port = process.env.PORT || 3000;

const userSchema = z.object({
  username: z.string().min(3).max(255).trim(),
  password: z.string().min(6).max(20).trim(),
});

const taskSchema = z.object({
  title: z.string().min(1).trim(),
  description: z.string().optional(),
  completed: z.boolean().optional(),
});

const userSchemaMongoose = new mongoose.Schema({
  username: { type: string, required: true, unique: true },
  password: { type: string, required: true, minlength: 6 },
});

const taskSchemaMongoose = new mongoose.Schema({
  title: { type: String, required: true },
  description: { type: String },
  completed: { type: Boolean, default: false },
  user: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
});

const User = mongoose.model("User", userSchemaMongoose);
const Task = mongoose.model("Task", taskSchemaMongoose);

const connectDB = async () => {
  try {
    await mongoose.connect(process.env.MONGODB_URL);
  } catch (err) {
    console.log(err);
    process.exit(1);
  }
};

connectDB();

const middlewares = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ error: "Unauthorized" });
    }
    const token = authHeader.split("")[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(403).json({ error: "Forbidden" });
  }
};

app.use(cors());
app.use(express.json());

app.post("/signup", async (req, res) => {
  try {
    const { username, password } = req.body;
    const validUser = userSchema.safeParse(req.body);
    if (!validUser.success) {
      return res.status(400).json(validUser.error.issues);
    }
    const existingUser = await User.findOne({ username });
    if (existingUser) {
      throw createError(409, "Username already exists");
    }
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    const newUser = new User({ username, password: hashedPassword });
    await newUser.save();

    const payload = { userId: newUser._id };
    const token = jwt.sign(payload, process.env.JWT_SECRET);
    res.json({ token });
  } catch {}
});

app.post("/signin", async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (!user) {
      throw createError(401, "Invalid Credentials");
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      throw createError(401, "Invalid Credentials");
    }

    const payload = { userId: user._id };
  } catch {}
});
