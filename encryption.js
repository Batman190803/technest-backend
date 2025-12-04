// encryption.js
const crypto = require("crypto");

const ALGO = "aes-256-gcm";

if (!process.env.ENCRYPTION_KEY) {
  console.warn("⚠️ ENCRYPTION_KEY не заданий у .env – шифрування працювати не буде");
}

const KEY = process.env.ENCRYPTION_KEY
  ? Buffer.from(process.env.ENCRYPTION_KEY, "hex")
  : null;

// шифруємо рядок у форматі iv:tag:cipher (усе hex)
function encryptText(plain) {
  if (plain === null || plain === undefined) return plain;
  if (!KEY) return plain; // fallback, якщо ключ не заданий

  const iv = crypto.randomBytes(12); // 12 байт для GCM
  const cipher = crypto.createCipheriv(ALGO, KEY, iv);

  let encrypted = cipher.update(String(plain), "utf8", "hex");
  encrypted += cipher.final("hex");

  const tag = cipher.getAuthTag();

  return `${iv.toString("hex")}:${tag.toString("hex")}:${encrypted}`;
}

function isProbablyEncrypted(value) {
  if (typeof value !== "string") return false;
  const parts = value.split(":");
  if (parts.length !== 3) return false;
  return parts.every((p) => /^[0-9a-fA-F]+$/.test(p));
}

function decryptText(stored) {
  if (stored === null || stored === undefined) return stored;
  if (!KEY) return stored;
  if (typeof stored !== "string") return stored;
  if (!isProbablyEncrypted(stored)) return stored; // старі plain-дані

  try {
    const [ivHex, tagHex, encHex] = stored.split(":");
    const iv = Buffer.from(ivHex, "hex");
    const tag = Buffer.from(tagHex, "hex");

    const decipher = crypto.createDecipheriv(ALGO, KEY, iv);
    decipher.setAuthTag(tag);

    let decrypted = decipher.update(encHex, "hex", "utf8");
    decrypted += decipher.final("utf8");
    return decrypted;
  } catch (e) {
    console.error("Decrypt error, повертаю як є:", e.message);
    return stored;
  }
}

function encryptFields(obj, fieldNames) {
  if (!obj) return obj;
  for (const field of fieldNames) {
    if (Object.prototype.hasOwnProperty.call(obj, field) && obj[field] != null) {
      const val = obj[field];
      if (typeof val === "string" && isProbablyEncrypted(val)) continue;
      obj[field] = encryptText(val);
    }
  }
  return obj;
}

function decryptFields(obj, fieldNames) {
  if (!obj) return obj;
  for (const field of fieldNames) {
    if (Object.prototype.hasOwnProperty.call(obj, field) && obj[field] != null) {
      obj[field] = decryptText(obj[field]);
    }
  }
  return obj;
}

module.exports = {
  encryptText,
  decryptText,
  encryptFields,
  decryptFields,
};
