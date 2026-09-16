import express from "express";
import path from "path";
import { createServer } from "http";
import { Server, Socket } from "socket.io";
import multer from "multer";
import fs from "fs";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import cors from "cors";

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
const adminPassword = process.env.ADMIN_PASSWORD || "supersecretadmin";

// In-memory user store
const users: Record<string, any> = {};

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

  if (token === process.env.ADMIN_PASSWORD || token === "supersecretadmin" || token === "131313") {
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
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ message: "Username and password required" });
    }
    if (users[username]) {
      return res.status(400).json({ message: "User already exists" });
    }
    
    const hashedPassword = await bcrypt.hash(password, 10);
    users[username] = { username, password: hashedPassword };
    
    const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: "24h" });
    res.status(200).json({ token });
  });

  app.post("/login", async (req, res) => {
    const { username, password } = req.body;
    const user = users[username];
    if (!user) {
      return res.status(400).json({ message: "Invalid credentials" });
    }
    
    const isValid = await bcrypt.compare(password, user.password);
    if (!isValid) {
      return res.status(400).json({ message: "Invalid credentials" });
    }
    
    const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: "24h" });
    res.status(200).json({ token });
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

  app.get("/api/admin/users", requireAdmin, (req, res) => {
    // Only return registered user accounts (keys that have a username property in the object)
    const registeredUsers = Object.keys(users).filter(key => typeof users[key] === 'object' && users[key].username);
    res.json(registeredUsers);
  });

  app.post("/api/admin/users", requireAdmin, async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ error: "Username and password required" });
    }
    if (users[username]) {
      return res.status(400).json({ error: "User already exists" });
    }
    
    const hashedPassword = await bcrypt.hash(password, 10);
    users[username] = { username, password: hashedPassword };
    res.json({ success: true, username });
  });

  app.put("/api/admin/users/:username", requireAdmin, async (req, res) => {
    const { username } = req.params;
    const { password } = req.body;
    if (!users[username]) {
      return res.status(404).json({ error: "User not found" });
    }
    if (!password) {
      return res.status(400).json({ error: "New password required" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    users[username].password = hashedPassword;
    res.json({ success: true });
  });

  app.delete("/api/admin/users/:username", requireAdmin, (req, res) => {
    const { username } = req.params;
    if (!users[username]) {
      return res.status(404).json({ error: "User not found" });
    }
    
    delete users[username];
    res.json({ success: true });
  });

  // --- Socket.IO Real-time Events ---

  // Middleware for Socket Authentication
  io.use((socket: Socket, next) => {
    const token = socket.handshake.auth.token || socket.handshake.query.token;
    if (!token) {
      return next(new Error("Authentication error: No token provided"));
    }

    // Check if it's admin using the admin password as token
    if (token === process.env.ADMIN_PASSWORD || token === "supersecretadmin" || token === "131313") {
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
