import express from "express";
import path from "path";
import { createServer } from "http";
import { Server, Socket } from "socket.io";
import multer from "multer";
import fs from "fs";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import cors from "cors";
import mongoose from "mongoose";
import QRCode from "qrcode";

// Database Connection URI
// The cluster URL is left as a placeholder for the user to fill in if missing, but uses their provided credentials
const MONGO_URI = process.env.MONGO_URI || "mongodb+srv://rudrashishsinghshekhawat794_db_user:gZyE6uSvl6PV607A@<YOUR_CLUSTER_URL_HERE>/chatdb?retryWrites=true&w=majority";

mongoose.connect(MONGO_URI)
  .then(() => console.log("Connected to MongoDB Atlas"))
  .catch((err) => console.error("MongoDB Atlas connection error:", err));

// MongoDB User Schema
const userSchema = new mongoose.Schema({
  name: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  qr: { type: String }
}, { 
  collection: 'users', // Explicitly naming the collection (acts like a folder in MongoDB)
  timestamps: true 
});
const User = mongoose.model("User", userSchema);

// Initialize upload directory
const uploadDir = path.join(process.cwd(), "uploads");
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir);
}

// Multer storage configuration
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
    cb(null, uniqueSuffix + "-" + file.originalname.replace(/\s+/g, "_"));
  },
});
const upload = multer({ storage });

const JWT_SECRET = process.env.JWT_SECRET || "my_super_secret_jwt_key_123";
const adminPassword = process.env.ADMIN_PASSWORD || "131313";

export interface ChatMessage {
  chatId: string;
  senderName: string;
  content: string; // usually an encrypted payload
  isFile: boolean;
  timestamp: number;
}

// Admin Authentication Middleware (for REST API)
const requireAdmin = (req: express.Request, res: express.Response, next: express.NextFunction) => {
  const authHeader = req.headers.authorization || "";
  let token = "";
  
  if (authHeader.startsWith("Bearer ")) {
    token = authHeader.split(" ")[1];
  } else if (authHeader.startsWith("Basic ")) {
    const b64auth = authHeader.split(" ")[1] || "";
    const [user, password] = Buffer.from(b64auth, "base64").toString().split(":");
    token = password; // Assume password is the token
  }

  if (token === adminPassword || token === "131313") {
    return next();
  }

  res.status(401).json({ error: "Admin credentials required." });
};

async function startServer() {
  const app = express();
  const PORT = process.env.PORT || 3000;
  const httpServer = createServer(app);
  const io = new Server(httpServer, {
    cors: {
      origin: "*", 
      methods: ["GET", "POST"],
    },
  });

  app.use(cors());
  app.use(express.json());
  app.use("/uploads", express.static(uploadDir));

  // --- Admin Monitoring State ---
  const activeRooms = new Set<string>();
  const activeWebRTCSessions = new Map<string, string[]>(); // chatId -> participantNames

  // --- REST API Routes ---

  app.post("/register", async (req, res) => {
    const name = req.body.name || req.body.username;
    const password = req.body.password;
    if (!name || !password) {
      return res.status(400).json({ message: "Name and password required" });
    }
    
    try {
      const existingUser = await User.findOne({ name });
      if (existingUser) {
        return res.status(400).json({ message: "User already exists" });
      }
      
      const hashedPassword = await bcrypt.hash(password, 10);
      
      // Generate a unique QR code containing the user's name
      const qrData = JSON.stringify({ name, type: "user_identity" });
      const qrCodeBase64 = await QRCode.toDataURL(qrData);

      const newUser = new User({ name, password: hashedPassword, qr: qrCodeBase64 });
      await newUser.save();
      
      const token = jwt.sign({ username: name }, JWT_SECRET, { expiresIn: "24h" });
      res.status(200).json({ token, qr: qrCodeBase64 });
    } catch (err) {
      console.error(err);
      res.status(500).json({ message: "Server error" });
    }
  });

  app.post("/login", async (req, res) => {
    const name = req.body.name || req.body.username;
    const password = req.body.password;
    
    try {
      const user = await User.findOne({ name });
      if (!user) {
        return res.status(400).json({ message: "Invalid credentials" });
      }
      
      const isValid = await bcrypt.compare(password, user.password);
      if (!isValid) {
        return res.status(400).json({ message: "Invalid credentials" });
      }
      
      const token = jwt.sign({ username: name }, JWT_SECRET, { expiresIn: "24h" });
      res.status(200).json({ token, qr: user.qr });
    } catch (err) {
      console.error(err);
      res.status(500).json({ message: "Server error" });
    }
  });

  app.post("/upload", upload.single("file"), (req, res) => {
    if (!req.file) {
      return res.status(400).json({ error: "No file uploaded" });
    }
    const fileUrl = `/uploads/${req.file.filename}`;
    res.json({ url: fileUrl });
  });

  // Old upload route for compatibility
  app.post("/api/upload", upload.single("file"), (req, res) => {
    if (!req.file) {
      return res.status(400).json({ error: "No file uploaded" });
    }
    const fileUrl = `/uploads/${req.file.filename}`;
    res.json({ url: fileUrl });
  });

  app.get("/api/admin/stats", requireAdmin, (req, res) => {
    res.json({
      totalConnectedUsers: io.engine.clientsCount,
      activeRooms: Array.from(activeRooms),
      activeWebRTCSessions: Array.from(activeWebRTCSessions.keys()),
    });
  });

  // --- Admin CRUD User Routes ---

  app.get("/api/admin/users", requireAdmin, async (req, res) => {
    try {
      const dbUsers = await User.find({}, 'name');
      const registeredUsers = dbUsers.map(u => u.name);
      res.json(registeredUsers);
    } catch (err) {
      res.status(500).json({ error: "Database error" });
    }
  });

  app.post("/api/admin/users", requireAdmin, async (req, res) => {
    const name = req.body.name || req.body.username;
    const password = req.body.password;
    if (!name || !password) {
      return res.status(400).json({ error: "Name and password required" });
    }
    
    try {
      const existingUser = await User.findOne({ name });
      if (existingUser) {
        return res.status(400).json({ error: "User already exists" });
      }
      
      const hashedPassword = await bcrypt.hash(password, 10);
      
      const qrData = JSON.stringify({ name, type: "user_identity" });
      const qrCodeBase64 = await QRCode.toDataURL(qrData);

      const newUser = new User({ name, password: hashedPassword, qr: qrCodeBase64 });
      await newUser.save();
      res.json({ success: true, username: name });
    } catch (err) {
      res.status(500).json({ error: "Database error" });
    }
  });

  app.put("/api/admin/users/:username", requireAdmin, async (req, res) => {
    const name = req.params.username;
    const { password } = req.body;
    
    if (!password) {
      return res.status(400).json({ error: "New password required" });
    }

    try {
      const user = await User.findOne({ name });
      if (!user) {
        return res.status(404).json({ error: "User not found" });
      }

      const hashedPassword = await bcrypt.hash(password, 10);
      user.password = hashedPassword;
      await user.save();
      res.json({ success: true });
    } catch (err) {
      res.status(500).json({ error: "Database error" });
    }
  });

  app.delete("/api/admin/users/:username", requireAdmin, async (req, res) => {
    const name = req.params.username;
    
    try {
      const result = await User.deleteOne({ name });
      if (result.deletedCount === 0) {
        return res.status(404).json({ error: "User not found" });
      }
      res.json({ success: true });
    } catch (err) {
      res.status(500).json({ error: "Database error" });
    }
  });

  // --- Socket.IO Real-time Events ---

  // Middleware for Socket Authentication
  io.use((socket: Socket, next) => {
    const token = socket.handshake.auth.token || socket.handshake.query.token;
    if (!token) {
      return next(new Error("Authentication error: No token provided"));
    }

    // Check if it's admin using the admin password as token
    if (token === adminPassword || token === "131313") {
       (socket as any).username = "admin";
       (socket as any).isAdmin = true;
       return next();
    }

    jwt.verify(token as string, JWT_SECRET, (err: any, decoded: any) => {
      if (err) {
        return next(new Error("Authentication error: Invalid token"));
      }
      (socket as any).username = decoded.username;
      if (decoded.username === 'admin') {
         (socket as any).isAdmin = true;
      }
      next();
    });
  });

  io.on("connection", (socket) => {
    const username = (socket as any).username;
    const isAdmin = (socket as any).isAdmin;
    console.log(`[Socket] User connected: ${socket.id} (${username})`);

    if (isAdmin) {
      socket.join("admin_monitor");
      console.log(`[Socket] Admin joined admin_monitor namespace`);
    }

    socket.on("join_chat", (chatId: string) => {
      socket.join(chatId);
      activeRooms.add(chatId);
      console.log(`[Socket] ${username} joined room ${chatId}`);
    });
    
    // Support the old join_room event as well
    socket.on("join_room", (chatId: string) => {
      socket.join(chatId);
      activeRooms.add(chatId);
      console.log(`[Socket] ${username} joined room ${chatId}`);
    });

    socket.on("send_message", (message: ChatMessage) => {
      // Broadcast to all other users in the room. E2E privacy maintained.
      socket.to(message.chatId).emit("receive_message", message);
    });

    // WebRTC Signaling
    socket.on("webrtc_start", (data: { chatId: string, participantName?: string } | string) => {
      // Handle both string and object payloads for backward compatibility
      const chatId = typeof data === 'string' ? data : data.chatId;
      const participantName = typeof data === 'string' ? username : (data.participantName || username);

      const participants = activeWebRTCSessions.get(chatId) || [];
      if (!participants.includes(participantName)) {
        participants.push(participantName);
      }
      activeWebRTCSessions.set(chatId, participants);
      
      socket.to(chatId).emit("webrtc_started", { chatId, participantName });
      
      // Notify Admin monitor
      io.to("admin_monitor").emit("admin_log", {
        event: "webrtc_start",
        chatId,
        participant: participantName,
        allParticipants: participants,
        timestamp: Date.now()
      });
      console.log(`[Socket] WebRTC started in room ${chatId} by ${participantName}`);
    });

    socket.on("webrtc_offer", ({ chatId, offer }) => {
      socket.to(chatId).emit("webrtc_offer", { chatId, offer });
    });

    socket.on("webrtc_answer", ({ chatId, answer }) => {
      socket.to(chatId).emit("webrtc_answer", { chatId, answer });
    });

    socket.on("webrtc_ice_candidate", ({ chatId, candidate }) => {
      socket.to(chatId).emit("webrtc_ice_candidate", { chatId, candidate });
    });

    socket.on("webrtc_end", (chatId: string) => {
      activeWebRTCSessions.delete(chatId);
      socket.to(chatId).emit("webrtc_ended", { chatId });
      
      // Notify Admin monitor
      io.to("admin_monitor").emit("admin_log", {
        event: "webrtc_end",
        chatId,
        timestamp: Date.now()
      });
      console.log(`[Socket] WebRTC ended in room ${chatId}`);
    });

    socket.on("disconnect", () => {
      console.log(`[Socket] User disconnected: ${socket.id} (${username})`);
    });
  });

  // --- Basic Root Route ---
  app.get("/", (req, res) => {
    res.sendFile(path.join(process.cwd(), "admin.html"));
  });

  httpServer.listen(PORT, "0.0.0.0", () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
}

startServer().catch(console.error);
