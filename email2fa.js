// email2fa.js
const axios = require("axios");
const crypto = require("crypto");

function generate2FACode() {
  return String(Math.floor(100000 + Math.random() * 900000));
}

function hashCode(code) {
  return crypto.createHash("sha256").update(code).digest("hex");
}

const MAILTRAP_TOKEN = process.env.MAILTRAP_TOKEN;
const MAILTRAP_FROM_EMAIL =
  process.env.MAILTRAP_FROM_EMAIL || "mailtrap@demomailtrap.co";
const MAILTRAP_FROM_NAME = process.env.MAILTRAP_FROM_NAME || "TechNest";

async function send2FACodeEmail(toEmail, code) {
  try {
    const res = await axios.post(
      "https://send.api.mailtrap.io/api/send",
      {
        from: {
          email: MAILTRAP_FROM_EMAIL,
          name: MAILTRAP_FROM_NAME,
        },
        to: [
          {
            email: toEmail, // <- сюди йде пошта користувача з реєстрації
          },
        ],
        subject: "Код підтвердження входу в TechNest",
        text: `Ваш код підтвердження: ${code}. Він дійсний 5 хвилин.`,
      },
      {
        headers: {
          Authorization: `Bearer ${MAILTRAP_TOKEN}`,
          "Content-Type": "application/json",
        },
        timeout: 10000,
      }
    );

    console.log("Mailtrap API response:", res.data);
  } catch (err) {
    console.error(
      "Mailtrap API error",
      err.response?.status,
      JSON.stringify(err.response?.data || {}, null, 2)
    );
    throw new Error("Не вдалося відправити лист 2FA");
  }
}

module.exports = {
  generate2FACode,
  hashCode,
  send2FACodeEmail,
};
