// email2fa.js
const crypto = require("crypto");

// 6-значний код
function generate2FACode() {
  return String(Math.floor(100000 + Math.random() * 900000));
}

function hashCode(code) {
  return crypto.createHash("sha256").update(code).digest("hex");
}

async function send2FACodeEmail(toEmail, code) {
  const token = process.env.MAILTRAP_TOKEN;
  const fromEmail = process.env.MAILTRAP_FROM_EMAIL;

  if (!token) {
    throw new Error("Mailtrap API token not configured");
  }
  if (!fromEmail) {
    throw new Error("Mailtrap FROM email not configured");
  }

  const url = "https://send.api.mailtrap.io/api/send";

  const payload = {
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
  };

  const res = await fetch(url, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(payload),
  });

  if (!res.ok) {
    let body = "";
    try {
      body = await res.text();
    } catch (e) {
      body = "<no body>";
    }
    console.error("Mailtrap API error", body);
    throw new Error("Не вдалося відправити лист 2FA");
  }
}

module.exports = {
  generate2FACode,
  hashCode,
  send2FACodeEmail,
};
