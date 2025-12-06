// email2fa.js
const axios = require("axios");
const crypto = require("crypto");

function generate2FACode() {
  return String(Math.floor(100000 + Math.random() * 900000));
}

function hashCode(code) {
  return crypto.createHash("sha256").update(code).digest("hex");
}

const MAILTRAP_API_TOKEN = process.env.MAILTRAP_TOKEN;
const MAILTRAP_FROM_EMAIL = process.env.MAILTRAP_FROM_EMAIL || "hello@demomailtrap.co";
const MAILTRAP_SENDER_NAME = process.env.MAILTRAP_SENDER_NAME || "TechNest";

async function send2FACodeEmail(toEmail, code) {
  if (!MAILTRAP_TOKEN) {
    console.error("MAILTRAP_API_TOKEN is missing");
    throw new Error("Mailtrap API token not configured");
  }

  const url = "https://send.api.mailtrap.io/api/send";

  const payload = {
    from: {
      email: MAILTRAP_FROM_EMAIL,
      name: MAILTRAP_SENDER_NAME,
    },
    to: [{ email: toEmail }],
    subject: "Код підтвердження входу в TechNest",
    text: `Ваш код підтвердження: ${code}. Він дійсний 5 хвилин.`,
  };

  try {
    const resp = await axios.post(url, payload, {
      headers: {
        Authorization: `Bearer ${MAILTRAP_TOKEN}`,
        "Content-Type": "application/json",
      },
    });

    console.log("Mailtrap API response:", resp.data);
  } catch (err) {
    if (err.response) {
      console.error("Mailtrap API error", err.response.data);
    } else {
      console.error("Mailtrap network error", err.message || err);
    }
    throw new Error("Не вдалося відправити лист 2FA");
  }
}

module.exports = {
  generate2FACode,
  hashCode,
  send2FACodeEmail,
};
