// email2fa.js
const axios = require("axios");
const crypto = require("crypto");

function generate2FACode() {
  // 6-значний код
  return String(Math.floor(100000 + Math.random() * 900000));
}

function hashCode(code) {
  return crypto.createHash("sha256").update(code).digest("hex");
}

async function send2FACodeEmail(toEmail, code) {
  const token = process.env.MAILTRAP_TOKEN;
  const fromEmail =
    process.env.MAILTRAP_FROM_EMAIL || "mailtrap@demomailtrap.io";

  if (!token) {
    console.error("[Mailtrap] MAILTRAP_TOKEN is not set");
    throw new Error("MAILTRAP_TOKEN не налаштований");
  }

  try {
    const response = await axios.post(
      "https://send.api.mailtrap.io/api/send",
      {
        from: {
          email: fromEmail,
          name: "TechNest",
        },
        to: [
          {
            email: toEmail,
          },
        ],
        subject: "Код підтвердження входу в TechNest",
        text: `Ваш код підтвердження: ${code}. Він дійсний 5 хвилин.`,
      },
      {
        headers: {
          // ❗ Головне: використовуємо саме Api-Token
          "Api-Token": token,
          "Content-Type": "application/json",
        },
      }
    );

    console.log("[Mailtrap] Email sent:", response.data);
  } catch (err) {
    console.error(
      "Mailtrap API error",
      err.response?.data || err.message || err
    );
    throw new Error("Не вдалося відправити лист 2FA");
  }
}

module.exports = {
  generate2FACode,
  hashCode,
  send2FACodeEmail,
};
