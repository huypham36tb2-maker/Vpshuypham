// server.js
// VPS Panel - Node.js + Express + SQLite + SSH
//
// Cài:
//   npm install express express-session better-sqlite3 bcryptjs cors helmet morgan dotenv ssh2
//
// Chạy:
//   node server.js
//
// Biến môi trường:
//   PORT=3000
//   SESSION_SECRET=change-this-secret
//   ADMIN_USER=admin
//   ADMIN_PASSWORD=change-this-password

require("dotenv").config();

const express = require("express");
const session = require("express-session");
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const cors = require("cors");
const helmet = require("helmet");
const morgan = require("morgan");
const { Client } = require("ssh2");
const path = require("path");
const crypto = require("crypto");

const app = express();
const PORT = Number(process.env.PORT || 3000);

app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({
  origin: true,
  credentials: true
}));
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(morgan("dev"));

app.use(session({
  secret: process.env.SESSION_SECRET || crypto.randomBytes(32).toString("hex"),
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    maxAge: 24 * 60 * 60 * 1000
  }
}));

// --------------------------------------------------
// DATABASE
// --------------------------------------------------

const db = new Database("vps-panel.db");

db.pragma("journal_mode = WAL");

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS vps (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    host TEXT NOT NULL,
    port INTEGER NOT NULL DEFAULT 22,
    username TEXT NOT NULL,
    auth_type TEXT NOT NULL DEFAULT 'password',
    password TEXT,
    private_key TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    action TEXT NOT NULL,
    vps_id INTEGER,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  );
`);

// Tạo admin mặc định nếu chưa có.
const adminUser = process.env.ADMIN_USER || "admin";
const adminPassword = process.env.ADMIN_PASSWORD || "admin123";

const existingAdmin = db
  .prepare("SELECT id FROM users WHERE username = ?")
  .get(adminUser);

if (!existingAdmin) {
  const hash = bcrypt.hashSync(adminPassword, 12);

  db.prepare(`
    INSERT INTO users (username, password, role)
    VALUES (?, ?, 'admin')
  `).run(adminUser, hash);

  console.log("======================================");
  console.log("Admin created");
  console.log("Username:", adminUser);
  console.log("Password:", adminPassword);
  console.log("Hãy đổi mật khẩu ngay sau khi đăng nhập.");
  console.log("======================================");
}

// --------------------------------------------------
// HELPERS
// --------------------------------------------------

function auth(req, res, next) {
  if (!req.session.user) {
    return res.status(401).json({
      error: "UNAUTHORIZED",
      message: "Bạn chưa đăng nhập."
    });
  }

  next();
}

function adminOnly(req, res, next) {
  if (!req.session.user) {
    return res.status(401).json({
      error: "UNAUTHORIZED"
    });
  }

  if (req.session.user.role !== "admin") {
    return res.status(403).json({
      error: "FORBIDDEN",
      message: "Chỉ Admin mới được thực hiện thao tác này."
    });
  }

  next();
}

function logAction(req, action, vpsId = null) {
  try {
    db.prepare(`
      INSERT INTO logs (user_id, action, vps_id)
      VALUES (?, ?, ?)
    `).run(
      req.session.user?.id || null,
      action,
      vpsId
    );
  } catch (_) {}
}

function getVps(id) {
  return db.prepare("SELECT * FROM vps WHERE id = ?").get(id);
}

function sanitizeVps(vps) {
  if (!vps) return null;

  return {
    id: vps.id,
    name: vps.name,
    host: vps.host,
    port: vps.port,
    username: vps.username,
    auth_type: vps.auth_type,
    created_at: vps.created_at
  };
}

// --------------------------------------------------
// SSH
// --------------------------------------------------

function sshConnect(vps) {
  return new Promise((resolve, reject) => {
    const conn = new Client();

    conn.on("ready", () => {
      resolve(conn);
    });

    conn.on("error", err => {
      reject(err);
    });

    const config = {
      host: vps.host,
      port: Number(vps.port || 22),
      username: vps.username,
      readyTimeout: 10000
    };

    if (vps.auth_type === "privateKey") {
      config.privateKey = vps.private_key;
    } else {
      config.password = vps.password;
    }

    conn.connect(config);
  });
}

function execSSH(vps, command) {
  return new Promise(async (resolve, reject) => {
    let conn;

    try {
      conn = await sshConnect(vps);

      conn.exec(command, (err, stream) => {
        if (err) {
          conn.end();
          return reject(err);
        }

        let stdout = "";
        let stderr = "";

        stream.on("data", data => {
          stdout += data.toString();
        });

        stream.stderr.on("data", data => {
          stderr += data.toString();
        });

        stream.on("close", (code) => {
          conn.end();

          resolve({
            code,
            stdout,
            stderr
          });
        });
      });
    } catch (err) {
      if (conn) conn.end();
      reject(err);
    }
  });
}

// --------------------------------------------------
// HEALTH
// --------------------------------------------------

app.get("/api/health", (req, res) => {
  res.json({
    ok: true,
    service: "VPS Panel",
    time: new Date().toISOString()
  });
});

// --------------------------------------------------
// AUTH
// --------------------------------------------------

app.post("/api/auth/login", (req, res) => {
  const { username, password } = req.body || {};

  if (!username || !password) {
    return res.status(400).json({
      error: "USERNAME_PASSWORD_REQUIRED"
    });
  }

  const user = db
    .prepare("SELECT * FROM users WHERE username = ?")
    .get(username);

  if (!user || !bcrypt.compareSync(password, user.password)) {
    return res.status(401).json({
      error: "INVALID_LOGIN",
      message: "Sai tài khoản hoặc mật khẩu."
    });
  }

  req.session.user = {
    id: user.id,
    username: user.username,
    role: user.role
  };

  res.json({
    success: true,
    user: req.session.user
  });
});

app.post("/api/auth/logout", auth, (req, res) => {
  req.session.destroy(() => {
    res.json({
      success: true
    });
  });
});

app.get("/api/auth/me", (req, res) => {
  if (!req.session.user) {
    return res.json({
      authenticated: false
    });
  }

  res.json({
    authenticated: true,
    user: req.session.user
  });
});

// --------------------------------------------------
// USERS - ADMIN
// --------------------------------------------------

app.get("/api/users", adminOnly, (req, res) => {
  const users = db.prepare(`
    SELECT id, username, role, created_at
    FROM users
    ORDER BY id DESC
  `).all();

  res.json(users);
});

app.post("/api/users", adminOnly, (req, res) => {
  const {
    username,
    password,
    role = "user"
  } = req.body || {};

  if (!username || !password) {
    return res.status(400).json({
      error: "USERNAME_PASSWORD_REQUIRED"
    });
  }

  if (!["admin", "user"].includes(role)) {
    return res.status(400).json({
      error: "INVALID_ROLE"
    });
  }

  try {
    const hash = bcrypt.hashSync(password, 12);

    const result = db.prepare(`
      INSERT INTO users (username, password, role)
      VALUES (?, ?, ?)
    `).run(username, hash, role);

    res.json({
      success: true,
      id: result.lastInsertRowid
    });
  } catch (err) {
    res.status(400).json({
      error: "USER_EXISTS_OR_INVALID",
      message: err.message
    });
  }
});

app.delete("/api/users/:id", adminOnly, (req, res) => {
  const id = Number(req.params.id);

  if (id === req.session.user.id) {
    return res.status(400).json({
      error: "CANNOT_DELETE_SELF"
    });
  }

  db.prepare("DELETE FROM users WHERE id = ?").run(id);

  res.json({
    success: true
  });
});

// --------------------------------------------------
// VPS
// --------------------------------------------------

app.get("/api/vps", auth, (req, res) => {
  const rows = db.prepare(`
    SELECT id, name, host, port, username, auth_type, created_at
    FROM vps
    ORDER BY id DESC
  `).all();

  res.json(rows);
});

app.get("/api/vps/:id", auth, (req, res) => {
  const vps = getVps(Number(req.params.id));

  if (!vps) {
    return res.status(404).json({
      error: "VPS_NOT_FOUND"
    });
  }

  res.json(sanitizeVps(vps));
});

app.post("/api/vps", adminOnly, (req, res) => {
  const {
    name,
    host,
    port = 22,
    username,
    auth_type = "password",
    password,
    private_key
  } = req.body || {};

  if (!name || !host || !username) {
    return res.status(400).json({
      error: "NAME_HOST_USERNAME_REQUIRED"
    });
  }

  if (!["password", "privateKey"].includes(auth_type)) {
    return res.status(400).json({
      error: "INVALID_AUTH_TYPE"
    });
  }

  if (auth_type === "password" && !password) {
    return res.status(400).json({
      error: "SSH_PASSWORD_REQUIRED"
    });
  }

  if (auth_type === "privateKey" && !private_key) {
    return res.status(400).json({
      error: "PRIVATE_KEY_REQUIRED"
    });
  }

  const result = db.prepare(`
    INSERT INTO vps
    (name, host, port, username, auth_type, password, private_key)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(
    name,
    host,
    Number(port),
    username,
    auth_type,
    auth_type === "password" ? password : null,
    auth_type === "privateKey" ? private_key : null
  );

  logAction(req, "CREATE_VPS", result.lastInsertRowid);

  res.json({
    success: true,
    id: result.lastInsertRowid
  });
});

app.delete("/api/vps/:id", adminOnly, (req, res) => {
  const id = Number(req.params.id);

  const vps = getVps(id);

  if (!vps) {
    return res.status(404).json({
      error: "VPS_NOT_FOUND"
    });
  }

  db.prepare("DELETE FROM vps WHERE id = ?").run(id);

  logAction(req, "DELETE_VPS", id);

  res.json({
    success: true
  });
});

// --------------------------------------------------
// VPS STATUS
// --------------------------------------------------

app.get("/api/vps/:id/status", auth, async (req, res) => {
  const id = Number(req.params.id);
  const vps = getVps(id);

  if (!vps) {
    return res.status(404).json({
      error: "VPS_NOT_FOUND"
    });
  }

  try {
    const result = await execSSH(
      vps,
      "printf 'ONLINE\\n'; uptime"
    );

    res.json({
      online: result.code === 0,
      output: result.stdout.trim()
    });
  } catch (err) {
    res.json({
      online: false,
      error: err.message
    });
  }
});

// --------------------------------------------------
// VPS STATS
// --------------------------------------------------

app.get("/api/vps/:id/stats", auth, async (req, res) => {
  const id = Number(req.params.id);
  const vps = getVps(id);

  if (!vps) {
    return res.status(404).json({
      error: "VPS_NOT_FOUND"
    });
  }

  const command = `
echo "CPU=$(top -bn1 | awk '/Cpu\$begin:math:text$s\\$end:math:text$/ {print 100 - $8}')"
echo "RAM=$(free | awk '/Mem:/ {printf "%.2f", $3/$2*100}')"
echo "DISK=$(df -P / | awk 'NR==2 {print $5}')"
echo "UPTIME=$(uptime -p 2>/dev/null || uptime)"
`;

  try {
    const result = await execSSH(vps, command);

    const stats = {};

    result.stdout
      .split("\n")
      .forEach(line => {
        const index = line.indexOf("=");

        if (index === -1) return;

        const key = line.slice(0, index);
        const value = line.slice(index + 1);

        stats[key] = value;
      });

    res.json({
      success: true,
      stats
    });
  } catch (err) {
    res.status(500).json({
      error: "SSH_ERROR",
      message: err.message
    });
  }
});

// --------------------------------------------------
// VPS ACTIONS
// --------------------------------------------------

const ACTIONS = {
  start: "sudo systemctl start networking 2>/dev/null || true",
  stop: "sudo shutdown -h now",
  restart: "sudo reboot"
};

app.post("/api/vps/:id/action", auth, async (req, res) => {
  const id = Number(req.params.id);
  const { action } = req.body || {};

  const vps = getVps(id);

  if (!vps) {
    return res.status(404).json({
      error: "VPS_NOT_FOUND"
    });
  }

  if (!["start", "stop", "restart"].includes(action)) {
    return res.status(400).json({
      error: "INVALID_ACTION"
    });
  }

  // Lưu ý:
  // Start/Stop VPS thật sự thường phải dùng API của nhà cung cấp VPS.
  // SSH không thể bật một máy đã tắt hoàn toàn.
  if (action === "start") {
    return res.status(400).json({
      error: "START_REQUIRES_PROVIDER_API",
      message: "Muốn bật VPS đã shutdown cần API của nhà cung cấp VPS."
    });
  }

  try {
    const result = await execSSH(vps, ACTIONS[action]);

    logAction(req, action.toUpperCase(), id);

    res.json({
      success: true,
      action,
      output: result.stdout,
      errorOutput: result.stderr
    });
  } catch (err) {
    res.status(500).json({
      error: "ACTION_FAILED",
      message: err.message
    });
  }
});

// --------------------------------------------------
// TERMINAL
// --------------------------------------------------

app.post("/api/vps/:id/terminal", auth, async (req, res) => {
  const id = Number(req.params.id);
  const { command } = req.body || {};

  const vps = getVps(id);

  if (!vps) {
    return res.status(404).json({
      error: "VPS_NOT_FOUND"
    });
  }

  if (!command || typeof command !== "string") {
    return res.status(400).json({
      error: "COMMAND_REQUIRED"
    });
  }

  // Giới hạn kích thước command.
  if (command.length > 10000) {
    return res.status(400).json({
      error: "COMMAND_TOO_LONG"
    });
  }

  try {
    const result = await execSSH(vps, command);

    logAction(req, "TERMINAL_COMMAND", id);

    res.json({
      success: true,
      code: result.code,
      stdout: result.stdout,
      stderr: result.stderr
    });
  } catch (err) {
    res.status(500).json({
      error: "SSH_ERROR",
      message: err.message
    });
  }
});

// --------------------------------------------------
// FILE MANAGER
// --------------------------------------------------

app.get("/api/vps/:id/files", auth, async (req, res) => {
  const id = Number(req.params.id);
  const vps = getVps(id);

  if (!vps) {
    return res.status(404).json({
      error: "VPS_NOT_FOUND"
    });
  }

  let directory = req.query.path || "~";

  // Không cho null byte.
  if (directory.includes("\0")) {
    return res.status(400).json({
      error: "INVALID_PATH"
    });
  }

  try {
    const command = `
cd -- ${shellQuote(directory)} &&
find . -maxdepth 1 -mindepth 1 -printf '%y|%s|%TY-%Tm-%Td %TH:%TM:%TS|%f\\n' 2>/dev/null
`;

    const result = await execSSH(vps, command);

    if (result.code !== 0) {
      return res.status(400).json({
        error: "DIRECTORY_ERROR",
        message: result.stderr
      });
    }

    const files = result.stdout
      .split("\n")
      .filter(Boolean)
      .map(line => {
        const parts = line.split("|");

        return {
          type: parts[0] === "d" ? "directory" : "file",
          size: Number(parts[1] || 0),
          modified: parts[2],
          name: parts.slice(3).join("|")
        };
      });

    res.json({
      path: directory,
      files
    });
  } catch (err) {
    res.status(500).json({
      error: "SSH_ERROR",
      message: err.message
    });
  }
});

app.post("/api/vps/:id/files/mkdir", auth, async (req, res) => {
  const id = Number(req.params.id);
  const vps = getVps(id);

  const {
    path: directory,
    name
  } = req.body || {};

  if (!vps) {
    return res.status(404).json({
      error: "VPS_NOT_FOUND"
    });
  }

  if (!directory || !name) {
    return res.status(400).json({
      error: "PATH_NAME_REQUIRED"
    });
  }

  try {
    const command = `
cd -- ${shellQuote(directory)} &&
mkdir -- ${shellQuote(name)}
`;

    const result = await execSSH(vps, command);

    if (result.code !== 0) {
      return res.status(400).json({
        error: "MKDIR_FAILED",
        message: result.stderr
      });
    }

    logAction(req, "CREATE_DIRECTORY", id);

    res.json({
      success: true
    });
  } catch (err) {
    res.status(500).json({
      error: "SSH_ERROR",
      message: err.message
    });
  }
});

app.delete("/api/vps/:id/files", auth, async (req, res) => {
  const id = Number(req.params.id);
  const vps = getVps(id);
  const target = req.query.path;

  if (!vps) {
    return res.status(404).json({
      error: "VPS_NOT_FOUND"
    });
  }

  if (!target) {
    return res.status(400).json({
      error: "PATH_REQUIRED"
    });
  }

  try {
    const command = `
rm -rf -- ${shellQuote(target)}
`;

    const result = await execSSH(vps, command);

    if (result.code !== 0) {
      return res.status(400).json({
        error: "DELETE_FAILED",
        message: result.stderr
      });
    }

    logAction(req, "DELETE_FILE", id);

    res.json({
      success: true
    });
  } catch (err) {
    res.status(500).json({
      error: "SSH_ERROR",
      message: err.message
    });
  }
});

// --------------------------------------------------
// RENAME
// --------------------------------------------------

app.post("/api/vps/:id/files/rename", auth, async (req, res) => {
  const id = Number(req.params.id);
  const vps = getVps(id);

  const {
    oldPath,
    newPath
  } = req.body || {};

  if (!vps) {
    return res.status(404).json({
      error: "VPS_NOT_FOUND"
    });
  }

  if (!oldPath || !newPath) {
    return res.status(400).json({
      error: "OLD_NEW_PATH_REQUIRED"
    });
  }

  try {
    const command = `
mv -- ${shellQuote(oldPath)} ${shellQuote(newPath)}
`;

    const result = await execSSH(vps, command);

    if (result.code !== 0) {
      return res.status(400).json({
        error: "RENAME_FAILED",
        message: result.stderr
      });
    }

    logAction(req, "RENAME_FILE", id);

    res.json({
      success: true
    });
  } catch (err) {
    res.status(500).json({
      error: "SSH_ERROR",
      message: err.message
    });
  }
});

// --------------------------------------------------
// LOGS
// --------------------------------------------------

app.get("/api/logs", adminOnly, (req, res) => {
  const logs = db.prepare(`
    SELECT
      logs.id,
      logs.action,
      logs.vps_id,
      logs.created_at,
      users.username
    FROM logs
    LEFT JOIN users
      ON users.id = logs.user_id
    ORDER BY logs.id DESC
    LIMIT 500
  `).all();

  res.json(logs);
});

// --------------------------------------------------
// STATIC FRONTEND
// --------------------------------------------------

app.use(express.static(path.join(__dirname, "public")));

app.get("*", (req, res) => {
  if (req.path.startsWith("/api/")) {
    return res.status(404).json({
      error: "API_NOT_FOUND"
    });
  }

  res.sendFile(
    path.join(__dirname, "public", "index.html")
  );
});

// --------------------------------------------------
// SHELL QUOTE
// --------------------------------------------------

function shellQuote(value) {
  return "'" +
    String(value)
      .replace(/'/g, "'\\''") +
    "'";
}

// --------------------------------------------------
// ERROR HANDLER
// --------------------------------------------------

app.use((err, req, res, next) => {
  console.error(err);

  res.status(500).json({
    error: "INTERNAL_SERVER_ERROR"
  });
});

// --------------------------------------------------
// START
// --------------------------------------------------

app.listen(PORT, () => {
  console.log("");
  console.log("======================================");
  console.log(" VPS PANEL");
  console.log("======================================");
  console.log(` Server: http://localhost:${PORT}`);
  console.log(` Database: ${path.resolve("vps-panel.db")}`);
  console.log("======================================");
});
