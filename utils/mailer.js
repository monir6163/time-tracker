const nodemailer = require("nodemailer");

let transporter = null;

function getTransporter() {
  if (transporter) return transporter;

  const { SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS } = process.env;
  if (!SMTP_HOST || !SMTP_USER || !SMTP_PASS) {
    // Not configured — invite endpoint will fall back to returning the
    // join link so the admin can share it manually (WhatsApp, etc).
    return null;
  }

  transporter = nodemailer.createTransport({
    host: SMTP_HOST,
    port: Number(SMTP_PORT) || 587,
    secure: Number(SMTP_PORT) === 465,
    auth: { user: SMTP_USER, pass: SMTP_PASS },
  });
  return transporter;
}

async function sendInviteEmail({ to, teamName, inviteLink, inviterName }) {
  const t = getTransporter();
  if (!t) return { sent: false };

  await t.sendMail({
    from: process.env.SMTP_FROM || process.env.SMTP_USER,
    to,
    subject: `${inviterName} invited you to join ${teamName} on TimeTrack`,
    html: `
      <p>Hi,</p>
      <p><strong>${inviterName}</strong> invited you to join <strong>${teamName}</strong> on TimeTrack.</p>
      <p><a href="${inviteLink}">Click here to accept the invite</a></p>
      <p>Or open the app and register with team code shown in your invite link.</p>
    `,
  });

  return { sent: true };
}

async function sendNotificationEmail({ to, subject, message }) {
  const t = getTransporter();
  if (!t) return { sent: false };

  await t.sendMail({
    from: process.env.SMTP_FROM || process.env.SMTP_USER,
    to,
    subject,
    text: message,
    html: `<p>${message.replace(/\n/g, "<br />")}</p>`,
  });
  return { sent: true };
}

async function sendPasswordResetEmail({ to, resetLink }) {
  return sendNotificationEmail({
    to,
    subject: "Reset your TimeTrack password",
    message: `Use this link to reset your password. It expires in 30 minutes:\n${resetLink}`,
  });
}

module.exports = {
  sendInviteEmail,
  sendNotificationEmail,
  sendPasswordResetEmail,
};
