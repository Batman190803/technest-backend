require("dotenv").config();
console.log("SMTP_HOST =", process.env.SMTP_HOST);
console.log("SMTP_PORT =", process.env.SMTP_PORT);

const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const fs = require("fs");
const multer = require("multer");
const { PDFParse } = require("pdf-parse");
const { PrismaClient } = require("@prisma/client");

// Покращена функція витягування тексту з PDF
async function extractTextFromPDF(filePath) {
  try {
    console.log('[PDF] Початок витягування тексту з:', filePath);

    const dataBuffer = await fs.promises.readFile(filePath);

    // Використовуємо PDFParse v2 API
    const parser = new PDFParse({
      data: dataBuffer,
      verbosity: 0 // Вимкнути детальні логи
    });

    try {
      const result = await parser.getText();
      const text = result.text?.trim();

      if (text && text.length > 10) {
        console.log(`[PDF] ✅ Успішно витягнуто ${text.length} символів`);
        console.log(`[PDF] Сторінок: ${result.pages || result.numPages || 'невідомо'}`);
        return text;
      } else {
        console.warn('[PDF] ⚠️ Текст занадто короткий або порожній');
        return null;
      }
    } catch (parseError) {
      console.error('[PDF] Помилка парсингу:', parseError.message);
      return null;
    }

  } catch (error) {
    console.error('[PDF] Критична помилка витягування тексту:', error);
    return null;
  }
}

const {
  generate2FACode,
  hashCode,
  send2FACodeEmail,
} = require("./email2fa");

const prisma = new PrismaClient();

const app = express();

const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET || "dev_secret_change_me";

const path = require("path");

// Створюємо постійну папку для документів
const DOCUMENTS_DIR = path.join(__dirname, "documents");
if (!fs.existsSync(DOCUMENTS_DIR)) {
  fs.mkdirSync(DOCUMENTS_DIR, { recursive: true });
}

// Налаштування multer для постійного зберігання
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, DOCUMENTS_DIR);
  },
  filename: (req, file, cb) => {
    // Унікальне ім'я: timestamp-userId-assetId-originalName
    const userId = req.user?.userId || "unknown";
    const assetId = req.params.assetId || "unknown";
    const timestamp = Date.now();
    const safeName = file.originalname.replace(/[^a-zA-Z0-9.-]/g, "_");
    cb(null, `${timestamp}-${userId}-${assetId}-${safeName}`);
  },
});

const upload = multer({
  storage,
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB ліміт
  fileFilter: (req, file, cb) => {
    // Дозволені типи файлів
    const allowedTypes = [
      'application/pdf',
      'image/jpeg',
      'image/jpg',
      'image/png',
      'application/msword',
      'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
    ];
    if (allowedTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Непідтримуваний тип файлу. Дозволені: PDF, JPEG, PNG, DOC, DOCX'));
    }
  }
});

app.use(cors());
app.use(
  express.json({
    limit: "1mb", // достатньо під наші снапшоти
  })
);

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

// ====== OpenAI ініціалізація ======
let openai = null;
try {
  const OpenAI = require("openai");

  if (!process.env.OPENAI_API_KEY) {
    console.warn(
      "[OPENAI] OPENAI_API_KEY is not set. /api/ai/chat буде недоступний."
    );
  } else {
    openai = new OpenAI({
      apiKey: process.env.OPENAI_API_KEY,
    });
    console.log("[OPENAI] клієнт ініціалізовано");
  }
} catch (e) {
  console.error("[OPENAI] Помилка ініціалізації:", e);
}

// ====== хелпер для створення токена ======
function signToken(user) {
  return jwt.sign(
    { userId: user.id, username: user.username, role: user.role },
    JWT_SECRET,
    { expiresIn: "7d" }
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

app.post("/api/auth/register", async (req, res) => {
  try {
    const { username, password, email } = req.body;

    if (!username || !password || !email || password.length < 4) {
      return res
        .status(400)
        .json({ error: "Вкажіть логін, пароль (мін. 4 символи) та email" });
    }

    // Перевірка чи існує логін або пошта
    const existing = await prisma.user.findFirst({
      where: {
        OR: [{ username }, { email }],
      },
    });

    if (existing) {
      return res
        .status(400)
        .json({ error: "Такий логін або email уже існує" });
    }

    const passwordHash = await bcrypt.hash(password, 10);

    const user = await prisma.user.create({
      data: {
        username,
        passwordHash,
        email,
        role: username.toLowerCase() === "bilous" ? "admin" : "user",
      },
    });

    // Стандартні категорії
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

    const user = await prisma.user.findUnique({
      where: { username },
    });

    if (!user) {
      return res.status(400).json({ error: "Невірний логін або пароль" });
    }

    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) {
      return res.status(400).json({ error: "Невірний логін або пароль" });
    }

    // Старі акаунти без email заходять без 2FA
    if (!user.email) {
      const token = signToken(user);
      return res.json({
        token,
        user: { id: user.id, username: user.username, role: user.role },
        legacyNoEmail: true,
      });
    }

    // Нові акаунти з email — логін через 2FA по пошті
    const code = generate2FACode();
    const codeHash = hashCode(code);
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000); // 5 хв

    await prisma.user.update({
      where: { id: user.id },
      data: {
        twoFaCodeHash: codeHash,
        twoFaCodeExpiresAt: expiresAt,
        twoFaCodeUsed: false,
      },
    });

    await send2FACodeEmail(user.email, code);

    const twofaToken = jwt.sign(
      {
        userId: user.id,
        stage: "2fa_pending",
      },
      JWT_SECRET,
      { expiresIn: "10m" }
    );

    return res.json({
      status: "2fa_required",
      twofaToken,
    });
  } catch (e) {
    console.error("Login error", e);
    return res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/auth/verify-email-2fa", async (req, res) => {
  try {
    const { twofaToken, code } = req.body;

    if (!twofaToken || !code) {
      return res.status(400).json({ error: "Немає токена або коду" });
    }

    let payload;
    try {
      payload = jwt.verify(twofaToken, JWT_SECRET);
    } catch (e) {
      console.error("2FA token verify error", e);
      return res
        .status(401)
        .json({ error: "Невірний або прострочений 2FA токен" });
    }

    const userId = payload.userId;

    const user = await prisma.user.findUnique({ where: { id: userId } });
    if (!user) {
      return res.status(404).json({ error: "Користувача не знайдено" });
    }

    if (!user.twoFaCodeHash || !user.twoFaCodeExpiresAt) {
      return res.status(400).json({ error: "2FA код не збережений" });
    }

    const now = new Date();
    if (user.twoFaCodeExpiresAt < now) {
      return res.status(400).json({ error: "Код прострочений" });
    }

    if (user.twoFaCodeUsed) {
      return res.status(400).json({ error: "Код вже використаний" });
    }

    const codeHash = hashCode(code);
    if (codeHash !== user.twoFaCodeHash) {
      return res.status(400).json({ error: "Невірний код" });
    }

    await prisma.user.update({
      where: { id: user.id },
      data: { twoFaCodeUsed: true },
    });

    const finalToken = signToken(user);

    return res.json({
      status: "ok",
      token: finalToken,
      user: { id: user.id, username: user.username, role: user.role },
    });
  } catch (e) {
    console.error("verify-email-2fa error", e);
    res.status(500).json({ error: "Server error" });
  }
});

// Статистика користувача (для дашборду)
app.get("/api/stats", authMiddleware, async (req, res) => {
  try {
    const userId = req.user.userId;

    // Підрахунок документів
    const totalDocs = await prisma.assetDocument.count({
      where: { userId }
    });

    const docsWithText = await prisma.assetDocument.count({
      where: {
        userId,
        text: { not: null },
        AND: {
          text: { not: "" }
        }
      }
    });

    res.json({
      documents: {
        total: totalDocs,
        withText: docsWithText,
        withoutText: totalDocs - docsWithText
      }
    });
  } catch (e) {
    console.error("Stats error:", e);
    res.status(500).json({ error: "Помилка отримання статистики" });
  }
});

app.get("/api/debug/docs", authMiddleware, async (req, res) => {
  const userId = req.user.userId;
  const docs = await prisma.assetDocument.findMany({
    where: { userId },
    orderBy: { createdAt: "desc" },
  });
  res.json({ count: docs.length, docs });
});

// ====== AI ЧАТ ======
app.post("/api/ai/chat", authMiddleware, async (req, res) => {
  try {
    const userId = req.user.userId;
    const { message, assetId } = req.body; // Додаємо опціональний assetId

    if (!message) {
      return res.status(400).json({ error: "Повідомлення не може бути порожнім" });
    }

    console.log("AI CHAT for userId =", userId, "assetId =", assetId || "all");

    // 1) Отримуємо документи
    let docs;
    if (assetId) {
      // Якщо вказано assetId - беремо тільки документи цього активу
      docs = await prisma.assetDocument.findMany({
        where: {
          userId,
          assetId: assetId.toString()
        },
        orderBy: { createdAt: "desc" },
      });
      console.log(`Знайдено ${docs.length} документів для активу ${assetId}`);
    } else {
      // Інакше - беремо всі останні документи користувача
      docs = await prisma.assetDocument.findMany({
        where: { userId },
        take: 10, // Збільшуємо до 10 документів
        orderBy: { createdAt: "desc" },
      });
      console.log(`Знайдено ${docs.length} документів користувача`);
    }

    // 2) Формуємо контекст з документів
    let docsContext = "";
    if (docs.length > 0) {
      const docDescriptions = docs.map((d, index) => {
        const textPreview = d.text && d.text.trim()
          ? d.text.slice(0, 3000) // Збільшуємо до 3000 символів
          : "[Текст не було витягнуто з цього документа]";

        return `
📄 Документ ${index + 1}: ${d.fileName}
   Тип: ${d.mimeType}
   Розмір: ${d.fileSize ? (d.fileSize / 1024).toFixed(2) + ' KB' : 'невідомо'}
   Дата завантаження: ${new Date(d.createdAt).toLocaleDateString('uk-UA')}

Зміст документа:
${textPreview}
`;
      });

      docsContext = docDescriptions.join("\n" + "=".repeat(80) + "\n");
    } else {
      docsContext = assetId
        ? "Для цього активу ще не завантажено жодного документа."
        : "У вас ще немає завантажених документів.";
    }

    // 3) Отримуємо інформацію про активи з AssetSnapshot (зашифрований JSON)
    let categories = [];
    let totalAssets = 0;

    try {
      const snapshot = await prisma.assetSnapshot.findUnique({
        where: { userId }
      });

      if (snapshot && snapshot.data) {
        try {
          categories = decryptJson(snapshot.data);
          console.log(`[AI] Активів з snapshot для userId ${userId}:`, categories.length, 'категорій');

          // Підраховуємо загальну кількість активів
          totalAssets = categories.reduce((sum, cat) => sum + (cat.items?.length || 0), 0);
        } catch (decryptErr) {
          console.error('[AI] Помилка декодування активів:', decryptErr);
          categories = [];
        }
      } else {
        console.log(`[AI] Немає snapshot для userId ${userId}`);
      }
    } catch (snapshotErr) {
      console.error('[AI] Помилка читання snapshot:', snapshotErr);
      categories = [];
    }

    // Підраховуємо документи з текстом
    const docsWithText = docs.filter(d => d.text && d.text.trim().length > 0).length;

    let assetsContext = "";
    // Завжди показуємо статистику, навіть якщо немає активів
    assetsContext = `\n\n=== СТАТИСТИКА КОРИСТУВАЧА ===
Всього категорій обладнання: ${categories.length}
Всього одиниць обладнання: ${totalAssets}
Завантажено документів: ${docs.length}
Документів з розпізнаним текстом: ${docsWithText}
`;

    // Детальний список активів
    if (totalAssets > 0) {
      assetsContext += "\n=== ВАШЕ ОБЛАДНАННЯ ===\n";
      categories.forEach(cat => {
        const items = cat.items || [];
        if (items.length > 0) {
          assetsContext += `\n${cat.title} (${items.length} од.):\n`;
          items.forEach(asset => {
            assetsContext += `  - ${asset.name} (Інв.№ ${asset.inventoryNumber})`;
            if (asset.model) assetsContext += ` | Модель: ${asset.model}`;
            if (asset.room) assetsContext += ` | Кімната: ${asset.room}`;
            if (asset.responsible) assetsContext += ` | Відповідальний: ${asset.responsible}`;
            if (asset.status) assetsContext += ` | Статус: ${asset.status}`;
            assetsContext += '\n';
          });
        }
      });
    } else {
      assetsContext += "\n⚠️ У вас ще немає створених активів обладнання.\n";
      assetsContext += "Створіть активи через мобільний додаток, щоб AI міг надавати рекомендації з їх обслуговування.\n";
    }

    // 4) Формуємо системний промпт
    const systemPrompt = `Ти — AI асистент з технічного обслуговування для мобільного додатку TechNest.

ВАЖЛИВІ ПРАВИЛА:
- Відповідай ТІЛЬКИ українською мовою
- Будь конкретним і корисним
- Використовуй ТІЛЬКИ інформацію з наведених нижче документів та активів
- Якщо питання стосується кількості - використовуй СТАТИСТИКУ
- Якщо питання стосується документів - посилайся на конкретні документи
- Якщо в документах є технічні характеристики, інструкції або специфікації - цитуй їх
- Допомагай з питаннями обслуговування, ремонту, налаштування обладнання
- Якщо інформації немає в документах або статистиці - чесно скажи про це

${assetsContext}

ДОСТУПНІ ДОКУМЕНТИ:
${docsContext}

Тепер дай відповідь на запитання користувача, використовуючи ТІЛЬКИ наведену вище інформацію.`;

    // 5) Викликаємо OpenAI
    const completion = await openai.chat.completions.create({
      model: process.env.OPENAI_MODEL || "gpt-4o-mini",
      messages: [
        { role: "system", content: systemPrompt },
        { role: "user", content: message },
      ],
      temperature: 0.3,
      max_tokens: 1000,
    });

    const reply =
      completion.choices?.[0]?.message?.content ||
      "Не вдалося отримати відповідь від моделі.";

    console.log("AI відповідь надіслано успішно");

    res.json({
      reply,
      stats: {
        documentsTotal: docs.length,
        documentsWithText: docsWithText,
        categoriesCount: categories.length,
        assetsCount: totalAssets
      },
      hasAssetContext: !!assetId
    });
  } catch (err) {
    console.error("AI backend error:", err);
    res.status(500).json({
      error: "Помилка при зверненні до OpenAI",
      details: err.message
    });
  }
});




// ====== КЕРУВАННЯ ДОКУМЕНТАМИ АКТИВІВ ======

// Отримати всі документи конкретного активу
app.get("/api/assets/:assetId/documents", authMiddleware, async (req, res) => {
  try {
    const userId = req.user.userId;
    const assetId = req.params.assetId;

    const documents = await prisma.assetDocument.findMany({
      where: {
        userId,
        assetId: assetId.toString()
      },
      orderBy: { createdAt: "desc" },
      select: {
        id: true,
        fileName: true,
        mimeType: true,
        fileSize: true,
        createdAt: true,
        text: false // Не віддаємо весь text у списку
      }
    });

    res.json({
      assetId,
      count: documents.length,
      documents
    });
  } catch (err) {
    console.error("Get documents error:", err);
    res.status(500).json({ error: "Помилка отримання документів" });
  }
});

// Отримати конкретний документ з текстом
app.get("/api/documents/:documentId", authMiddleware, async (req, res) => {
  try {
    const userId = req.user.userId;
    const documentId = parseInt(req.params.documentId, 10);

    const document = await prisma.assetDocument.findFirst({
      where: {
        id: documentId,
        userId
      }
    });

    if (!document) {
      return res.status(404).json({ error: "Документ не знайдено" });
    }

    res.json({ document });
  } catch (err) {
    console.error("Get document error:", err);
    res.status(500).json({ error: "Помилка отримання документа" });
  }
});

// Переобробити PDF документ для витягування тексту
app.post("/api/documents/:documentId/reprocess", authMiddleware, async (req, res) => {
  try {
    const userId = req.user.userId;
    const documentId = parseInt(req.params.documentId, 10);

    const document = await prisma.assetDocument.findFirst({
      where: {
        id: documentId,
        userId
      }
    });

    if (!document) {
      return res.status(404).json({ error: "Документ не знайдено" });
    }

    if (document.mimeType !== "application/pdf") {
      return res.status(400).json({ error: "Тільки PDF документи можна переобробити" });
    }

    if (!document.filePath || !fs.existsSync(document.filePath)) {
      return res.status(404).json({ error: "Файл документа не знайдено на сервері" });
    }

    console.log(`Переобробка документа ID=${documentId}: ${document.fileName}`);

    // Витягуємо текст
    const text = await extractTextFromPDF(document.filePath);

    // Оновлюємо документ
    const updated = await prisma.assetDocument.update({
      where: { id: documentId },
      data: { text }
    });

    res.json({
      ok: true,
      message: "Документ переобробено",
      hasText: !!text,
      textLength: text ? text.length : 0
    });
  } catch (err) {
    console.error("Reprocess document error:", err);
    res.status(500).json({ error: "Помилка переобробки документа" });
  }
});

// Переобробити ВСІ PDF документи користувача
app.post("/api/documents/reprocess-all", authMiddleware, async (req, res) => {
  try {
    const userId = req.user.userId;

    const documents = await prisma.assetDocument.findMany({
      where: {
        userId,
        mimeType: "application/pdf"
      }
    });

    console.log(`Переобробка ${documents.length} PDF документів користувача ${userId}`);

    let processed = 0;
    let withText = 0;
    let errors = 0;

    for (const doc of documents) {
      try {
        if (doc.filePath && fs.existsSync(doc.filePath)) {
          const text = await extractTextFromPDF(doc.filePath);
          await prisma.assetDocument.update({
            where: { id: doc.id },
            data: { text }
          });
          processed++;
          if (text) withText++;
        }
      } catch (err) {
        console.error(`Помилка переобробки документа ${doc.id}:`, err);
        errors++;
      }
    }

    res.json({
      ok: true,
      total: documents.length,
      processed,
      withText,
      errors,
      message: `Переобробано ${processed} з ${documents.length} документів. Текст витягнуто з ${withText}.`
    });
  } catch (err) {
    console.error("Reprocess all documents error:", err);
    res.status(500).json({ error: "Помилка переобробки документів" });
  }
});

// Видалити документ
app.delete("/api/documents/:documentId", authMiddleware, async (req, res) => {
  try {
    const userId = req.user.userId;
    const documentId = parseInt(req.params.documentId, 10);

    const document = await prisma.assetDocument.findFirst({
      where: {
        id: documentId,
        userId
      }
    });

    if (!document) {
      return res.status(404).json({ error: "Документ не знайдено" });
    }

    // Видаляємо фізичний файл
    if (document.filePath && fs.existsSync(document.filePath)) {
      try {
        await fs.promises.unlink(document.filePath);
        console.log("Файл видалено:", document.filePath);
      } catch (unlinkError) {
        console.error("Помилка видалення файлу:", unlinkError);
        // Продовжуємо видалення запису з БД навіть якщо файл не вдалося видалити
      }
    }

    // Видаляємо запис з БД
    await prisma.assetDocument.delete({
      where: { id: documentId }
    });

    res.json({ ok: true, message: "Документ видалено" });
  } catch (err) {
    console.error("Delete document error:", err);
    res.status(500).json({ error: "Помилка видалення документа" });
  }
});

// ====== ЗАВАНТАЖЕННЯ ДОКУМЕНТІВ ДЛЯ АКТИВІВ ======
app.post(
  "/api/assets/:assetId/documents",
  authMiddleware,
  upload.single("file"),
  async (req, res) => {
    try {
      const userId = req.user.userId;
      const assetId = req.params.assetId;
      const file = req.file;

      if (!file) {
        return res.status(400).json({ error: "Файл не надійшов" });
      }

      console.log("UPLOAD DOCUMENT:", {
        userId,
        assetId,
        originalname: file.originalname,
        mimetype: file.mimetype,
        size: file.size,
        savedPath: file.path,
      });

      let text = null;
      if (file.mimetype === "application/pdf") {
        text = await extractTextFromPDF(file.path);
      }

      const doc = await prisma.assetDocument.create({
        data: {
          userId,
          assetId,
          fileName: file.originalname,
          mimeType: file.mimetype,
          filePath: file.path, // Зберігаємо шлях до файлу
          fileSize: file.size,
          text,
        },
      });

      console.log("DOCUMENT SAVED:", {
        id: doc.id,
        userId: doc.userId,
        assetId: doc.assetId,
        fileName: doc.fileName,
        filePath: doc.filePath,
        hasText: !!doc.text,
        textLength: doc.text ? doc.text.length : 0,
      });

      res.json({
        ok: true,
        document: {
          id: doc.id,
          fileName: doc.fileName,
          mimeType: doc.mimeType,
          fileSize: doc.fileSize,
          hasText: !!doc.text,
          createdAt: doc.createdAt,
        }
      });
    } catch (err) {
      console.error("Upload document error:", err);
      // Якщо помилка - видаляємо файл
      if (req.file?.path) {
        try {
          await fs.promises.unlink(req.file.path);
        } catch (unlinkError) {
          console.error("Не вдалося видалити файл після помилки:", unlinkError);
        }
      }
      res.status(500).json({ error: "Помилка завантаження документа" });
    }
  }
);

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

// Видалити актив
app.delete("/api/assets/items/:id", authMiddleware, async (req, res) => {
  try {
    const userId = req.user.userId;
    const id = parseInt(req.params.id, 10);

    console.log(`DELETE /api/assets/items/${id} for userId =`, userId);

    // Перевіряємо чи існує актив і чи належить він користувачу
    const asset = await prisma.asset.findUnique({
      where: { id },
      include: { category: true },
    });

    if (!asset) {
      return res.status(404).json({ error: "Актив не знайдено" });
    }

    if (asset.category.userId !== userId) {
      return res.status(403).json({ error: "Доступ заборонено" });
    }

    // Видаляємо актив
    await prisma.asset.delete({
      where: { id },
    });

    console.log(`✅ Актив ${id} (${asset.name}) видалено`);

    res.json({
      ok: true,
      message: "Актив успішно видалено",
      deletedAsset: {
        id: asset.id,
        name: asset.name,
        inventoryNumber: asset.inventoryNumber,
      },
    });
  } catch (e) {
    console.error("Delete asset error", e);
    res.status(500).json({ error: "Помилка сервера при видаленні активу" });
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

    // Отримуємо всі документи користувача для видалення файлів
    const userDocuments = await prisma.assetDocument.findMany({
      where: { userId },
      select: { filePath: true }
    });

    // Видаляємо фізичні файли документів
    for (const doc of userDocuments) {
      if (doc.filePath && fs.existsSync(doc.filePath)) {
        try {
          await fs.promises.unlink(doc.filePath);
          console.log("Видалено файл документа:", doc.filePath);
        } catch (err) {
          console.error("Помилка видалення файлу:", err);
        }
      }
    }

    // Видаляємо дані з БД (Prisma автоматично видалить пов'язані записи якщо є onDelete: Cascade)
    await prisma.asset.deleteMany({
      where: { category: { userId } },
    });
    await prisma.assetCategory.deleteMany({
      where: { userId },
    });
    await prisma.assetSnapshot.deleteMany({
      where: { userId },
    });
    await prisma.assetDocument.deleteMany({
      where: { userId },
    });
    await prisma.chatMessage.deleteMany({
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

    // Отримуємо всі документи користувача для видалення файлів
    const userDocuments = await prisma.assetDocument.findMany({
      where: { userId },
      select: { filePath: true }
    });

    // Видаляємо фізичні файли документів
    for (const doc of userDocuments) {
      if (doc.filePath && fs.existsSync(doc.filePath)) {
        try {
          await fs.promises.unlink(doc.filePath);
        } catch (err) {
          console.error("Помилка видалення файлу:", err);
        }
      }
    }

    await prisma.asset.deleteMany({
      where: { category: { userId } },
    });
    await prisma.assetCategory.deleteMany({
      where: { userId },
    });
    await prisma.assetSnapshot.deleteMany({
      where: { userId },
    });
    await prisma.assetDocument.deleteMany({
      where: { userId },
    });
    await prisma.chatMessage.deleteMany({
      where: { userId },
    });
    await prisma.user.delete({ where: { id: userId } });

    res.json({ ok: true });
  } catch (e) {
    console.error("Admin delete user error", e);
    res.status(500).json({ error: "Server error" });
  }
});

// ====== старт сервера ======
app.listen(PORT, () => {
  console.log(`TechNest backend listening on http://localhost:${PORT}`);
});
