// email2fa.js
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
  const fromEmail = process.env.MAILTRAP_FROM_EMAIL || "no-reply@technest.app";
  const fromName = process.env.MAILTRAP_FROM_NAME || "TechNest";

  if (!token) {
    console.error("MAILTRAP_TOKEN is not set");
    throw new Error("MAILTRAP_TOKEN is not set");
  }

  const res = await fetch("https://send.api.mailtrap.io/api/send", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      from: { email: fromEmail, name: fromName },
      to: [{ email: toEmail }],
      subject: "Код підтвердження входу в TechNest",
      text: `Ваш код підтвердження: ${code}. Він дійсний 5 хвилин.`,
      category: "2fa",
    }),
  });

  if (!res.ok) {
    const text = await res.text();
    console.error("Mailtrap API error", res.status, text);
    throw new Error("Не вдалося відправити лист 2FA");
  }
}

module.exports = {
  generate2FACode,
  hashCode,
  send2FACodeEmail,
};
