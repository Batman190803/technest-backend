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
  process.env.MAILTRAP_FROM_EMAIL || "mailtrap@demomailtrap.io";
const MAILTRAP_FROM_NAME = process.env.MAILTRAP_FROM_NAME || "TechNest";

async function send2FACodeEmail(toEmail, code) {
  if (!MAILTRAP_TOKEN) {
    console.error("MAILTRAP_TOKEN is not set");
    throw new Error("Mail service not configured");
  }

  try {
    const resp = await axios.post(
      "https://send.api.mailtrap.io/api/send",
      {
        from: {
          email: MAILTRAP_FROM_EMAIL,
          name: MAILTRAP_FROM_NAME,
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
          Authorization: `Bearer ${MAILTRAP_TOKEN}`,
          "Content-Type": "application/json",
        },
      }
    );

    console.log("Mailtrap API OK", resp.data);
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
