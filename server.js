 // server.js
const express = require("express");
const http = require("http");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const socketIO = require("socket.io");
const multer = require("multer");
const path = require("path");
require("dotenv").config();
const db = require("./db");
const redisClient = require("./redis");
const verifyToken = require("./middleware/auth");
const rateLimit = require("express-rate-limit");
const logger = require("./logger");
const crypto = require("crypto");


const app = express();
const server = http.createServer(app);
const userSockets = {}; // userId => [socketIds]

/* ================= RATE LIMITERS ================= */
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: "Too many login attempts, try again later",
});

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: "Too many requests, please try again later.",
});

/* ================= JWT HELPERS ================= */
const generateAccessToken = (user) =>
  jwt.sign({ id: user.id, username: user.username }, process.env.ACCESS_SECRET, {
    expiresIn: "2h",
  });

const generateRefreshToken = (user) =>
  jwt.sign({ id: user.id, username: user.username }, process.env.REFRESH_SECRET, {
    expiresIn: "7d",
  });

/* ================= MIDDLEWARE ================= */
app.use(cors({ origin: process.env.CLIENT_URL, credentials: true }));
app.use(express.json());
app.use("/uploads", express.static(path.join(__dirname, "uploads")));

/* ================= USER SEARCH ================= */
app.get("/search-user", verifyToken, async (req, res) => {
  try {
    const { username, userId } = req.query;
    if (!username) return res.status(400).json({ message: "Username is required" });

    const [rows] = await db.query(
      "SELECT id, username FROM users WHERE username LIKE ? AND id != ?",
      [`%${username}%`, userId]
    );
    res.json(rows);
  } catch (err) {
    console.error("❌ /search-user error:", err);
    res.status(500).json({ message: "Internal server error" });
  }
});

/* ================= ADD USER ================= */
app.post("/addUser", verifyToken, async (req, res) => {
  try {
    const { username, password, email } = req.body;
    if (!username || !password || !email) return res.status(400).json({ error: "All fields required" });

    const [existing] = await db.query("SELECT * FROM users WHERE username = ?", [username]);
    if (existing.length > 0) return res.status(400).json({ error: "Username already taken" });

    const hashedPassword = await bcrypt.hash(password, 10);
    const [result] = await db.query(
      "INSERT INTO users (username, password, email) VALUES (?,?,?)",
      [username, hashedPassword, email]
    );

    res.status(201).json({ message: "User added successfully", userId: result.insertId });
  } catch (err) {
    console.error("ADD USER ERROR:", err);
    if (err.code === "ER_DUP_ENTRY") return res.status(400).json({ error: "Username or Email already exists" });
    res.status(500).json({ error: err.message });
  }
});

/* ================= REGISTER ================= */
app.post("/register", authLimiter, async (req, res) => {
  try {
    const { username, email, password } = req.body;
    if (!username || !email || !password) return res.status(400).json({ message: "All fields required" });

    const hashed = await bcrypt.hash(password, 10);
    await db.query("INSERT INTO users(username,email,password) VALUES (?,?,?)", [username, email, hashed]);
    res.json({ message: "Registered successfully" });
  } catch (err) {
    console.error("REGISTER ERROR:", err);
    if (err.code === "ER_DUP_ENTRY") return res.status(400).json({ message: "Email already registered" });
    res.status(500).json({ message: "Server error" });
  }
});

/* ================= LOGIN ================= */
app.post("/login", authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;
    const [rows] = await db.query("SELECT * FROM users WHERE email=?", [email]);
    if (!rows.length) return res.status(401).json({ message: "Invalid credentials" });

    const user = rows[0];
    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(401).json({ message: "Invalid credentials" });

    const payload = { id: String(user.id), username: user.username };
    res.json({
      accessToken: generateAccessToken(payload),
      refreshToken: generateRefreshToken(payload),
      user: payload,
    });
  } catch (err) {
    console.error("LOGIN ERROR:", err);
    res.status(500).json({ message: "Server error" });
  }
});

/* ================= GET ALL USERS ================= */
app.get("/users", verifyToken, async (req, res) => {
  try {
    const [rows] = await db.query("SELECT id, username FROM users");
    res.json(rows);
  } catch (err) {
    console.error("❌ /users error:", err);
    res.status(500).json({ message: "Internal server error" });
  }
});

/* ================= CHAT USERS ================= */
app.get("/chat-users/:userId", verifyToken, async (req, res) => {
  try {
    const userId = req.params.userId;
    const sql = `
      SELECT DISTINCT
        CASE WHEN sender_id = ? THEN receiver_id ELSE sender_id END AS chat_user_id
      FROM messages
      WHERE sender_id = ? OR receiver_id = ?`;
    const [result] = await db.query(sql, [userId, userId, userId]);

    if (!result.length) return res.json([]);
    const ids = result.map((r) => r.chat_user_id);
    const [users] = await db.query("SELECT id, username FROM users WHERE id IN (?)", [ids]);

    res.json(users.map((u) => ({ id: String(u.id), username: u.username })));
  } catch (err) {
    console.error("CHAT USERS ERROR:", err);
    res.status(500).json({ message: "DB error" });
  }
});

/* ================= MESSAGES REST ================= */
app.get("/messages/:userId/:receiverId", verifyToken, async (req, res) => {
  try {
    const { userId, receiverId } = req.params;
    const limit = parseInt(req.query.limit) || 50;
    const offset = parseInt(req.query.offset) || 0;

    const [rows] = await db.query(
      `SELECT 
         id,
         sender_id AS sender,
         receiver_id AS receiver,
         message,
         status,
         type,
         media_url,
         reply_to,
         edited,
         created_at AS createdAt
       FROM messages
       WHERE (
      (sender_id=? AND receiver_id=? AND deleted_by_sender=0)
      OR
      (sender_id=? AND receiver_id=? AND deleted_by_receiver=0)
   )
       ORDER BY id DESC
       LIMIT ? OFFSET ?`,
      [userId, receiverId, receiverId, userId, limit, offset]
    );

    // Reverse so oldest messages come first
    const messages = rows.reverse().map((m) => ({
      id: m.id,
      sender: String(m.sender),
      receiver: String(m.receiver),
      message: m.message || "",
      status: m.status,
      type: m.type,
      mediaUrl: m.media_url || null,
      replyTo: (() => {if (!m.reply_to) return null;try {  return typeof m.reply_to === "string"  ? JSON.parse(m.reply_to)  : m.reply_to; } catch (err) { console.error("Reply parse error:", err);  return null; }})(),
      edited: !!m.edited,
      createdAt: m.createdAt,
    }));

    res.json(messages);
  } catch (err) {
    console.error("GET MESSAGES ERROR:", err);
    res.status(500).json({ error: err.message });
  }
});



/* ================= AUDIO UPLOAD ================= */
const audioStorage = multer.diskStorage({
  destination: "uploads/audio",
  filename: (req, file, cb) => cb(null, Date.now() + ".webm"),
});
const audioUpload = multer({ storage: audioStorage });
app.post("/upload-audio", audioUpload.single("audio"), (req, res) => {
  res.json({
    url: `${process.env.BASE_URL}/uploads/audio/${req.file.filename}`,
  });
});


/* ================= MEDIA UPLOAD ================= */
const mediaStorage = multer.diskStorage({
  destination: (req, file, cb) => {
    if (file.mimetype.startsWith("image")) cb(null, "uploads/images");
    else if (file.mimetype.startsWith("video")) cb(null, "uploads/videos");
    else cb(new Error("Unsupported file type"), null);
  },
  filename: (req, file, cb) => cb(null, crypto.randomUUID() + path.extname(file.originalname)),
});

const allowedImageTypes = ["image/jpeg", "image/png", "image/gif", "image/webp"];
const allowedVideoTypes = ["video/mp4", "video/webm", "video/ogg"];

const mediaUpload = multer({
  storage: mediaStorage,
  limits: { fileSize: 400 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith("image") && allowedImageTypes.includes(file.mimetype)) cb(null, true);
    else if (file.mimetype.startsWith("video") && allowedVideoTypes.includes(file.mimetype)) cb(null, true);
    else cb(new Error("Unsupported file type"));
  },
});

app.post("/upload-media", verifyToken, mediaUpload.single("file"), (req, res) => {
  if (!req.file) return res.status(400).json({ message: "No file uploaded" });

  const folder = req.file.mimetype.startsWith("image") ? "images" : "videos";

  res.json({
    url: `${process.env.BASE_URL}/uploads/${folder}/${req.file.filename}`,
  });
});


/* ================= SOCKET.IO ================= */
const io = socketIO(server, {
  cors: { origin: process.env.CLIENT_URL, methods: ["GET", "POST"] },
});

io.use((socket, next) => {
  try {
    const token = socket.handshake.auth.token;
    const decoded = jwt.verify(token, process.env.ACCESS_SECRET);
    socket.userId = String(decoded.id);
    next();
  } catch {
    next(new Error("Invalid or expired token"));
  }
});




/* ================= ONLINE USERS ================= */
const broadcastOnlineUsers = async () => {
  const users = await redisClient.sMembers("onlineUsers");
  io.emit("onlineUsers", users);
};

io.on("connection", async (socket) => {
 

  logger.info(`User connected: ${socket.userId}`);
  socket.join(socket.userId);

  // Track this socket for the user
if (!userSockets[socket.userId]) userSockets[socket.userId] = [];
userSockets[socket.userId].push(socket.id);
  await redisClient.sAdd("onlineUsers", socket.userId);
  await broadcastOnlineUsers();

  // DELIVER OFFLINE MESSAGES
  const offlineMessages = await redisClient.lRange(`offline:${socket.userId}`, 0, -1);
  for (const msg of offlineMessages) socket.emit("receiveMessage", JSON.parse(msg));
  await redisClient.del(`offline:${socket.userId}`);


  // SEND MESSAGE
socket.on("sendMessage", async ({ receiver, message, mediaUrl, type, replyTo }) => {
  if (!receiver) return;

  const senderId = socket.userId;
  const receiverId = String(receiver);
  const isOnline = await redisClient.sIsMember("onlineUsers", receiverId);
  const status = isOnline ? "delivered" : "sent";

  try {
    const [result] = await db.query(
      `INSERT INTO messages 
       (sender_id, receiver_id, message, status, type, media_url, reply_to) 
       VALUES (?,?,?,?,?,?,?)`,
      [
        senderId,
        receiverId,
        message || null,
        status,
        type || "text",
        mediaUrl || null,
        replyTo ? JSON.stringify(replyTo) : null  // ✅ SAVE REPLY
      ]
    );

    const msg = {
      id: result.insertId,
      sender: senderId,
      receiver: receiverId,
      message: message || "",
      status,
      type: type || "text",
      mediaUrl: mediaUrl || null,
      replyTo: replyTo || null,   // ✅ EMIT REPLY
      createdAt: new Date(),
    };

    socket.emit("receiveMessage", msg);

    if (isOnline) {
      io.to(receiverId).emit("receiveMessage", msg);
    } else {
      await redisClient.rPush(`offline:${receiverId}`, JSON.stringify(msg));
    }

  } catch (err) {
    logger.error("MESSAGE INSERT ERROR:", err);
  }
});


  // MESSAGE SEEN
  socket.on("markSeen", async ({ senderId }) => {
    const receiverId = socket.userId;
    await db.query(
      "UPDATE messages SET status='seen' WHERE sender_id=? AND receiver_id=? AND status!='seen'",
      [senderId, receiverId]
    );
    io.to(String(senderId)).emit("messagesSeen", { senderId: receiverId });
  });


  /* ================= DELETE MESSAGE ================= */
socket.on("deleteMessage", async ({ messageId, type }) => {
  try {
    const userId = socket.userId;

    const [rows] = await db.query(
      "SELECT sender_id, receiver_id FROM messages WHERE id=?",
      [messageId]
    );

    if (!rows.length) return;

    const { sender_id, receiver_id } = rows[0];

    // =========================
    // DELETE FOR ME
    // =========================
    if (type === "me") {
      if (userId == sender_id) {
        await db.query(
          "UPDATE messages SET deleted_by_sender=1 WHERE id=?",
          [messageId]
        );
      } else {
        await db.query(
          "UPDATE messages SET deleted_by_receiver=1 WHERE id=?",
          [messageId]
        );
      }

      io.to(String(userId)).emit("messageDeletedForMe", { messageId });
    }

    // =========================
    // DELETE FOR EVERYONE
    // =========================
if (type === "everyone") {
  if (userId != sender_id) return;

  await db.query(
    "UPDATE messages SET deleted_by_sender=1, deleted_by_receiver=1 WHERE id=?",
    [messageId]
  );

  // Emit to **all sockets** of sender
  (userSockets[sender_id] || []).forEach((sid) =>
    io.to(sid).emit("messageDeletedForEveryone", { messageId })
  );

  // Emit to **all sockets** of receiver
  (userSockets[receiver_id] || []).forEach((sid) =>
    io.to(sid).emit("messageDeletedForEveryone", { messageId })
  );
}


  } catch (err) {
    logger.error("DELETE MESSAGE ERROR:", err);
  }
});


/* ================= EDIT MESSAGE ================= */
socket.on("editMessage", async ({ messageId, newText }) => {
  try {
    const userId = socket.userId;

    const [rows] = await db.query(
      "SELECT sender_id, receiver_id FROM messages WHERE id=?",
      [messageId]
    );

    if (!rows.length) return;

    const { sender_id, receiver_id } = rows[0];

    // Only sender can edit
    if (String(sender_id) !== String(userId)) return;

    await db.query(
      "UPDATE messages SET message=?, edited=1 WHERE id=?",
      [newText, messageId]
    );

    const payload = {
      messageId,
      newText,
    };

    // Emit to all sender sockets
    (userSockets[sender_id] || []).forEach((sid) =>
      io.to(sid).emit("messageEdited", payload)
    );

    // Emit to all receiver sockets
    (userSockets[receiver_id] || []).forEach((sid) =>
      io.to(sid).emit("messageEdited", payload)
    );

  } catch (err) {
    logger.error("EDIT MESSAGE ERROR:", err);
  }
});




  // AUDIO / VIDEO CALL EVENTS
  socket.on("callUser", ({ to, offer }) => io.to(to).emit("incomingCall", { from: socket.userId, offer }));
  socket.on("acceptCall", ({ to, answer }) => io.to(to).emit("callAccepted", { answer }));
  socket.on("iceCandidate", ({ to, candidate }) => io.to(to).emit("iceCandidate", { candidate }));

  // DISCONNECT
  socket.on("disconnect", async () => {
    const lastSeen = new Date();
    await db.query("UPDATE users SET last_seen=? WHERE id=?", [lastSeen, socket.userId]);
    await redisClient.sRem("onlineUsers", socket.userId);
    await broadcastOnlineUsers();
    io.emit("lastSeen", { userId: socket.userId, time: lastSeen });
  });




});

/* ================= START SERVER ================= */
const PORT = process.env.PORT || 5000;

server.listen(PORT, () => {
  console.log(`✅ Server running on port ${PORT}`);
});
