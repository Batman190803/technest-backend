require("dotenv").config();
const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const { PrismaClient } = require("@prisma/client");

const prisma = new PrismaClient();

const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET || "dev_secret_change_me";


const TWO_FA_SECRET = process.env.TWO_FA_SECRET || "dev_2fa_secret";

// ====== Налаштування шифрування ======
const ENC_ALGO = "aes-256-gcm";

// Ключ беремо як hex-рядок (64 символи) і конвертимо в Buffer
let ENC_KEY = null;
if (process.env.ENCRYPTION_KEY) {
  try {
    ENC_KEY = Buffer.from(process.env.ENCRYPTION_KEY, "hex");
    if (ENC_KEY.length !== 32) {
      console.error(
        "[ENCRYPTION] ENCRYPTION_KEY must be 32 bytes (64 hex chars). Got length:",
        ENC_KEY.length
      );
      ENC_KEY = null;
    }
  } catch (e) {
    console.error("[ENCRYPTION] Failed to parse ENCRYPTION_KEY from hex:", e);
    ENC_KEY = null;
  }
} else {
  console.warn(
    "[ENCRYPTION] ENCRYPTION_KEY is not set. Snapshots WILL NOT be encrypted!"
  );
}

// Шифруємо будь-який JS-об’єкт в base64-строку
function encryptJson(obj) {
  if (!ENC_KEY) {
    // fallback: без шифрування
    return JSON.stringify(obj);
  }
  const iv = crypto.randomBytes(12); // стандарт для GCM
  const cipher = crypto.createCipheriv(ENC_ALGO, ENC_KEY, iv);

  const json = JSON.stringify(obj);
  const enc = Buffer.concat([cipher.update(json, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();

  // Склеюємо: [iv(12b) | tag(16b) | ciphertext]
  const combined = Buffer.concat([iv, tag, enc]);
  return combined.toString("base64");
}

// Розшифровуємо base64-строку в JS-об’єкт
function decryptJson(str) {
  if (!str) return [];
  if (!ENC_KEY) {
    // fallback: значить зберігали без шифрування
    return JSON.parse(str);
  }

  try {
    const raw = Buffer.from(str, "base64");
    const iv = raw.subarray(0, 12);
    const tag = raw.subarray(12, 28);
    const enc = raw.subarray(28);

    const decipher = crypto.createDecipheriv(ENC_ALGO, ENC_KEY, iv);
    decipher.setAuthTag(tag);

    const dec = Buffer.concat([decipher.update(enc), decipher.final()]);
    return JSON.parse(dec.toString("utf8"));
  } catch (e) {
    console.error("[ENCRYPTION] decryptJson error, fallback to plain JSON:", e);
    // якщо раптом рядок — це не base64, а старий JSON
    return JSON.parse(str);
  }
}

const app = express();

app.use(cors());
app.use(
  express.json({
    limit: "1mb", // достатньо під наші снапшоти
  })
);

// ====== хелпер для створення токена ======
function signToken(user) {
  return jwt.sign(
    { userId: user.id, username: user.username, role: user.role },
    JWT_SECRET,
    { expiresIn: "7d" }
  );
}
const speakeasy = require("speakeasy");
// ==== 2FA: налаштування (генерація секрету) ====
// Користувач має бути залогінений (JWT), але twoFactorEnabled ще false
app.post("/api/auth/2fa/setup", authMiddleware, async (req, res) => {
  try {
    const userId = req.user.userId;

    const user = await prisma.user.findUnique({ where: { id: userId } });
    if (!user) return res.status(404).json({ error: "Користувач не знайдений" });

    // Генеруємо секрет для TOTP
    const secret = speakeasy.generateSecret({
      name: `TechNest (${user.username})`,
      length: 20,
    });

    // Зберігаємо ТІЛЬКИ base32 секрет у БД
    await prisma.user.update({
      where: { id: userId },
      data: {
        twoFactorSecret: secret.base32,
        twoFactorEnabled: false, // ще не підтверджено
      },
    });

    // Віддаємо otpauth URL, щоб RN міг зробити з нього QR
    res.json({
      otpauthUrl: secret.otpauth_url,
      base32: secret.base32, // на всякий випадок, але в UI головне otpauthUrl
    });
  } catch (e) {
    console.error("2FA setup error", e);
    res.status(500).json({ error: "Server error" });
  }
});
// ==== 2FA: підтвердження (включення) ====
app.post("/api/auth/2fa/confirm", authMiddleware, async (req, res) => {
  try {
    const userId = req.user.userId;
    const { token } = req.body; // 6-значний код з додатку

    if (!token) {
      return res.status(400).json({ error: "Введіть код підтвердження" });
    }

    const user = await prisma.user.findUnique({ where: { id: userId } });
    if (!user || !user.twoFactorSecret) {
      return res.status(400).json({ error: "2FA не налаштована" });
    }

    const verified = speakeasy.totp.verify({
      secret: user.twoFactorSecret,
      encoding: "base32",
      token,
      window: 1, // невелике вікно часу
    });

    if (!verified) {
      return res.status(400).json({ error: "Невірний код" });
    }

    await prisma.user.update({
      where: { id: userId },
      data: { twoFactorEnabled: true },
    });

    res.json({ ok: true });
  } catch (e) {
    console.error("2FA confirm error", e);
    res.status(500).json({ error: "Server error" });
  }
});

function signTwoFactorToken(user) {
  return jwt.sign(
    { userId: user.id, username: user.username, twoFactorPending: true },
    TWO_FA_SECRET,
    { expiresIn: "10m" } // 10 хвилин
  );
}


// ====== middleware для захисту роутів ======
function authMiddleware(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ error: "No token" });

  const [, token] = auth.split(" ");
  if (!token) return res.status(401).json({ error: "Invalid token format" });

  try {
    const payload = jwt.verify(token, JWT_SECRET);

    console.log("AUTH payload:", payload);

    req.user = payload; // { userId, username, role }
    next();
  } catch (e) {
    console.error("JWT verify error:", e);
    return res.status(401).json({ error: "Invalid or expired token" });
  }
}

// ====== ping ======
app.get("/api/health", (req, res) => {
  res.json({ status: "ok", time: new Date().toISOString() });
});

// ====== АВТЕНТИФІКАЦІЯ ======

// Реєстрація
app.post("/api/auth/register", async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password || password.length < 4) {
      return res
        .status(400)
        .json({ error: "Вкажіть логін і пароль (мін. 4 символи)" });
    }

    const existing = await prisma.user.findUnique({ where: { username } });
    if (existing) {
      return res.status(400).json({ error: "Такий логін уже існує" });
    }

    const passwordHash = await bcrypt.hash(password, 10);

    const user = await prisma.user.create({
      data: {
        username,
        passwordHash,
        role: username.toLowerCase() === "bilous" ? "admin" : "user",
      },
    });

    await prisma.assetCategory.createMany({
      data: [
        { title: "Комп'ютери", userId: user.id },
        { title: "Принтери та МФП", userId: user.id },
        { title: "Мережеве обладнання", userId: user.id },
        { title: "Транспорт", userId: user.id },
        { title: "Інше обладнання", userId: user.id },
      ],
    });

    const token = signToken(user);
    res.json({
      token,
      user: { id: user.id, username: user.username, role: user.role },
    });
  } catch (e) {
    console.error("Register error", e);
    res.status(500).json({ error: "Server error" });
  }
});

// Логін
app.post("/api/auth/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ error: "Вкажіть логін і пароль" });
    }

    const user = await prisma.user.findUnique({ where: { username } });
    if (!user) {
      return res.status(400).json({ error: "Невірний логін або пароль" });
    }

    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) {
      return res.status(400).json({ error: "Невірний логін або пароль" });
    }

    // 👉 Якщо 2FA увімкнена, не віддаємо основний JWT
    if (user.twoFactorEnabled && user.twoFactorSecret) {
      const tempToken = signTwoFactorToken(user);
      return res.json({
        twoFactorRequired: true,
        tempToken,
      });
    }

    // 👉 Якщо 2FA вимкнена — працюємо як раніше
    const token = signToken(user);
    res.json({
      token,
      user: { id: user.id, username: user.username, role: user.role },
    });
  } catch (e) {
    console.error("Login error", e);
    res.status(500).json({ error: "Server error" });
  }
});
// ==== 2FA: логін з кодом ====
app.post("/api/auth/2fa/login", async (req, res) => {
  try {
    const { tempToken, token } = req.body; 
    // tempToken — тимчасовий токен з /api/auth/login
    // token — 6-значний код з додатку

    if (!tempToken || !token) {
      return res.status(400).json({ error: "Немає tempToken або коду 2FA" });
    }

    let payload;
    try {
      payload = jwt.verify(tempToken, TWO_FA_SECRET);
    } catch (e) {
      console.error("2FA temp token verify error", e);
      return res.status(401).json({ error: "Невірний або прострочений tempToken" });
    }

    if (!payload.twoFactorPending || !payload.userId) {
      return res.status(400).json({ error: "Некоректний tempToken" });
    }

    const user = await prisma.user.findUnique({ where: { id: payload.userId } });
    if (!user || !user.twoFactorEnabled || !user.twoFactorSecret) {
      return res.status(400).json({ error: "2FA для користувача не активна" });
    }

    const verified = speakeasy.totp.verify({
      secret: user.twoFactorSecret,
      encoding: "base32",
      token,
      window: 1,
    });

    if (!verified) {
      return res.status(400).json({ error: "Невірний код 2FA" });
    }

    // Все ок: видаємо звичайний JWT
    const finalToken = signToken(user);
    res.json({
      token: finalToken,
      user: { id: user.id, username: user.username, role: user.role },
    });
  } catch (e) {
    console.error("2FA login error", e);
    res.status(500).json({ error: "Server error" });
  }
});


// ====== АКТИВИ ======

// Отримати всі категорії + активи поточного користувача
app.get("/api/assets", authMiddleware, async (req, res) => {
  try {
    const userId = req.user.userId;

    const categories = await prisma.assetCategory.findMany({
      where: { userId },
      include: {
        assets: true,
      },
      orderBy: { id: "asc" },
    });

    res.json(categories);
  } catch (e) {
    console.error("Get assets error", e);
    res.status(500).json({ error: "Server error" });
  }
});

// Створити нову категорію
app.post("/api/assets/categories", authMiddleware, async (req, res) => {
  try {
    const userId = req.user.userId;
    const { title } = req.body;
    if (!title) {
      return res.status(400).json({ error: "Вкажіть назву пункту" });
    }

    const category = await prisma.assetCategory.create({
      data: {
        title,
        userId,
      },
    });

    res.json(category);
  } catch (e) {
    console.error("Create category error", e);
    res.status(500).json({ error: "Server error" });
  }
});

// Додати актив у категорію
app.post("/api/assets/items", authMiddleware, async (req, res) => {
  try {
    const userId = req.user.userId;
    const {
      categoryId,
      name,
      inventoryNumber,
      model,
      serialNumber,
      status,
      room,
      responsible,
      phone,
      groupName,
      comments,
      qrCode,
    } = req.body;

    if (!categoryId || !name || !inventoryNumber) {
      return res.status(400).json({
        error: "Потрібні categoryId, name, inventoryNumber",
      });
    }

    const cat = await prisma.assetCategory.findFirst({
      where: { id: categoryId, userId },
    });
    if (!cat) {
      return res
        .status(403)
        .json({ error: "Категорія не знайдена або не ваша" });
    }

    const asset = await prisma.asset.create({
      data: {
        categoryId,
        name,
        inventoryNumber,
        model: model || null,
        serialNumber: serialNumber || null,
        status: status || null,
        room: room || null,
        responsible: responsible || null,
        phone: phone || null,
        groupName: groupName || null,
        comments: comments || null,
        qrCode: qrCode || null,
      },
    });

    res.json(asset);
  } catch (e) {
    console.error("Create asset error", e);
    res.status(500).json({ error: "Server error" });
  }
});

// Оновити актив
app.put("/api/assets/items/:id", authMiddleware, async (req, res) => {
  try {
    const userId = req.user.userId;
    const id = parseInt(req.params.id, 10);

    const asset = await prisma.asset.findUnique({
      where: { id },
      include: { category: true },
    });

    if (!asset || asset.category.userId !== userId) {
      return res.status(404).json({ error: "Актив не знайдено" });
    }

    const data = req.body;

    const updated = await prisma.asset.update({
      where: { id },
      data,
    });

    res.json(updated);
  } catch (e) {
    console.error("Update asset error", e);
    res.status(500).json({ error: "Server error" });
  }
});

// ====== АККАУНТ КОРИСТУВАЧА ======

app.post("/api/account/change-password", authMiddleware, async (req, res) => {
  try {
    const userId = req.user.userId;
    const { currentPassword, newPassword } = req.body;

    if (!currentPassword || !newPassword) {
      return res.status(400).json({ error: "Вкажіть поточний і новий пароль" });
    }

    const user = await prisma.user.findUnique({ where: { id: userId } });
    if (!user)
      return res.status(404).json({ error: "Користувач не знайдений" });

    const ok = await bcrypt.compare(currentPassword, user.passwordHash);
    if (!ok)
      return res.status(400).json({ error: "Невірний поточний пароль" });

    const newHash = await bcrypt.hash(newPassword, 10);
    await prisma.user.update({
      where: { id: userId },
      data: { passwordHash: newHash },
    });

    res.json({ ok: true });
  } catch (e) {
    console.error("Change password error", e);
    res.status(500).json({ error: "Server error" });
  }
});

app.delete("/api/account", authMiddleware, async (req, res) => {
  try {
    const userId = req.user.userId;

    await prisma.asset.deleteMany({
      where: { category: { userId } },
    });
    await prisma.assetCategory.deleteMany({
      where: { userId },
    });
    await prisma.assetSnapshot.deleteMany({
      where: { userId },
    });

    await prisma.user.delete({ where: { id: userId } });

    res.json({ ok: true });
  } catch (e) {
    console.error("Delete account error", e);
    res.status(500).json({ error: "Server error" });
  }
});

// ====== АДМІН ======

app.get("/api/admin/users", authMiddleware, async (req, res) => {
  try {
    if (req.user.role !== "admin") {
      return res.status(403).json({ error: "Доступ заборонено" });
    }

    const users = await prisma.user.findMany({
      select: { id: true, username: true, role: true },
      orderBy: { id: "asc" },
    });

    res.json({ users });
  } catch (e) {
    console.error("Admin users error", e);
    res.status(500).json({ error: "Server error" });
  }
});

app.post(
  "/api/admin/users/:username/role",
  authMiddleware,
  async (req, res) => {
    try {
      if (req.user.role !== "admin") {
        return res.status(403).json({ error: "Доступ заборонено" });
      }

      const username = req.params.username;
      const { role } = req.body;
      if (!role) return res.status(400).json({ error: "Вкажіть роль" });

      const user = await prisma.user.update({
        where: { username },
        data: { role },
        select: { id: true, username: true, role: true },
      });

      res.json({ user });
    } catch (e) {
      console.error("Admin set role error", e);
      res.status(500).json({ error: "Server error" });
    }
  }
);

app.delete("/api/admin/users/:username", authMiddleware, async (req, res) => {
  try {
    if (req.user.role !== "admin") {
      return res.status(403).json({ error: "Доступ заборонено" });
    }

    const username = req.params.username;

    const user = await prisma.user.findUnique({ where: { username } });
    if (!user)
      return res.status(404).json({ error: "Користувач не знайдений" });

    const userId = user.id;

    await prisma.asset.deleteMany({
      where: { category: { userId } },
    });
    await prisma.assetCategory.deleteMany({
      where: { userId },
    });
    await prisma.assetSnapshot.deleteMany({
      where: { userId },
    });
    await prisma.user.delete({ where: { id: userId } });

    res.json({ ok: true });
  } catch (e) {
    console.error("Admin delete user error", e);
    res.status(500).json({ error: "Server error" });
  }
});

// ==== СТАН АКТИВІВ (JSON снапшот) ====

// Отримати стан
app.get("/api/assets/state", authMiddleware, async (req, res) => {
  const userId = req.user.userId;

  console.log("GET /api/assets/state for userId =", userId);

  try {
    const snapshot = await prisma.assetSnapshot.findUnique({
      where: { userId },
    });

    let assetCategories = [];
    if (snapshot && snapshot.data) {
      try {
        assetCategories = decryptJson(snapshot.data);
        console.log(
          "Found snapshot for userId =",
          userId,
          "categories length =",
          Array.isArray(assetCategories)
            ? assetCategories.length
            : "not array"
        );
      } catch (e) {
        console.error("Decrypt assetSnapshot.data error", e);
      }
    } else {
      console.log("No snapshot for userId =", userId);
    }

    res.json({ assetCategories });
  } catch (e) {
    console.error("Assets get state error", e);
    res.status(500).json({ error: "Server error" });
  }
});

// Зберегти стан
app.post("/api/assets/state", authMiddleware, async (req, res) => {
  const userId = req.user.userId;
  const { assetCategories } = req.body;

  console.log(
    "PROTECT POST /api/assets/state for userId =",
    userId,
    "categories length =",
    Array.isArray(assetCategories) ? assetCategories.length : "not array"
  );

  if (!Array.isArray(assetCategories)) {
    return res
      .status(400)
      .json({ error: "assetCategories має бути масивом" });
  }

  if (assetCategories.length === 0) {
    console.log(
      "Skip saving EMPTY snapshot for userId =",
      userId,
      "(leave previous data unchanged)"
    );
    return res.json({ ok: true, skipped: true });
  }

  try {
    const data = encryptJson(assetCategories);

    const snapshot = await prisma.assetSnapshot.upsert({
      where: { userId },
      update: { data },
      create: { userId, data },
    });

    console.log(
      "Saved NON-EMPTY snapshot for userId =",
      userId,
      "bytes =",
      data.length
    );

    res.json({ ok: true, updatedAt: snapshot.updatedAt });
  } catch (e) {
    console.error("Assets save state error", e);
    res.status(500).json({ error: "Server error" });
  }
});

// ====== старт сервера ======
app.listen(PORT, () => {
  console.log(`TechNest backend listening on http://localhost:${PORT}`);
});
