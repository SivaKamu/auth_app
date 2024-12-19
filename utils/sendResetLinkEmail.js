const nodemailer = require('nodemailer');
const fs = require('fs');
const path = require('path');

const sendResetLinkEmail = (email, resetLink, userId) => {
  // Read the email template
  const templatePath = path.join(__dirname, 'templates', 'resetLinkTemplate.html');
  let emailTemplate = fs.readFileSync(templatePath, 'utf-8');

  // Replace the placeholder with the OTP
  emailTemplate = emailTemplate.replace('{{User}}', userId);
  emailTemplate = emailTemplate.replace('{{ResetLink}}', resetLink);

  const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: process.env.SMTP_PORT,
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS,
    },
  });

  const mailOptions = {
    from: `"11/4 Atti" <${process.env.SMTP_USER}>`,
    to: email,
    subject: 'Password Reset Request',
    html: emailTemplate,
  };

  transporter.sendMail(mailOptions, (error, info) => {
    if (error) {
      console.log('Error sending OTP email:', error);
    } else {
      console.log('OTP email sent:', info.response);
    }
  });

};

module.exports = sendResetLinkEmail;
