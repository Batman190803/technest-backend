// email2fa.js
const crypto = require("crypto");
const axios = require("axios");

function generate2FACode() {
  // 6-значний код
  return String(Math.floor(100000 + Math.random() * 900000));
}

function hashCode(code) {
  return crypto.createHash("sha256").update(code).digest("hex");
}

async function send2FACodeEmail(toEmail, code) {
  const token = process.env.MAILTRAP_TOKEN;
  const fromEmail = process.env.MAILTRAP_FROM_EMAIL || "mailtrap@demomailtrap.io";
  const fromName = process.env.MAILTRAP_FROM_NAME || "TechNest";

  if (!token) {
    console.error("MAILTRAP_TOKEN is not set");
    throw new Error("MAILTRAP_TOKEN is not set");
  }

  const payload = {
    from: {
      email: fromEmail,
      name: fromName,
    },
    to: [
      {
        email: toEmail,
      },
    ],
    subject: "Код підтвердження входу в TechNest",
    text: `Ваш код підтвердження: ${code}. Він дійсний 5 хвилин.`,
    category: "2fa",
  };

  try {
    const res = await axios.post(
      "https://send.api.mailtrap.io/api/send",
      payload,
      {
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
      }
    );

    console.log("Mailtrap API response status:", res.status);
  } catch (err) {
    if (err.response) {
      console.error("Mailtrap API error", err.response.status, err.response.data);
    } else {
      console.error("Mailtrap API error", err.message);
    }
    throw new Error("Не вдалося відправити лист 2FA");
  }
}

module.exports = {
  generate2FACode,
  hashCode,
  send2FACodeEmail,
};
