// email2fa.js
const nodemailer = require("nodemailer");
const crypto = require("crypto");

function generate2FACode() {
  return String(Math.floor(100000 + Math.random() * 900000));
}

function hashCode(code) {
  return crypto.createHash("sha256").update(code).digest("hex");
}

const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT) || 2525, // 👈 2525 за замовчуванням
  secure: false,
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
});

async function send2FACodeEmail(toEmail, code) {
  try {
    await transporter.sendMail({
      from: '"TechNest" <no-reply@technest.app>',
      to: toEmail,
      subject: "Код підтвердження входу в TechNest",
      text: `Ваш код підтвердження: ${code}. Він дійсний 5 хвилин.`,
    });
    console.log("2FA email sent to", toEmail);
  } catch (err) {
    console.error("❌ send2FACodeEmail error:", err);
    // ВАЖЛИВО: нічого не кидаємо далі, щоб логін не падав з 500
  }
}

module.exports = {
  generate2FACode,
  hashCode,
  send2FACodeEmail,
};
