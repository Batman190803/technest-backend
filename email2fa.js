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
  port: Number(process.env.SMTP_PORT) || 587,
  secure: false, // для 587
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
});

async function send2FACodeEmail(toEmail, code) {
  await transporter.sendMail({
    from: `"TechNest" <${process.env.SMTP_USER}>`, // ← щоб збігався з реальним ящиком
    to: toEmail,
    subject: "Код підтвердження входу в TechNest",
    text: `Ваш код підтвердження: ${code}. Він дійсний 5 хвилин.`,
  });
}

module.exports = {
  generate2FACode,
  hashCode,
  send2FACodeEmail,
};
