const nodemailer = require('nodemailer');
const fs = require('fs');
const path = require('path');

const sendOTPEmail = (email, otp, userId) => {
  // Read the email template
  const templatePath = path.join(__dirname, 'templates', 'otpTemplate.html');
  let emailTemplate = fs.readFileSync(templatePath, 'utf-8');

  // Replace the placeholder with the OTP
  emailTemplate = emailTemplate.replace('{{OTP}}', otp);
  emailTemplate = emailTemplate.replace('{{USERID}}', userId);

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
    subject: 'Your OTP Code',
    html: emailTemplate, // Use the updated template
  };

  transporter.sendMail(mailOptions, (error, info) => {
    if (error) {
      console.log('Error sending OTP email:', error);
    } else {
      console.log('OTP email sent:', info.response);
    }
  });
};

module.exports = sendOTPEmail;
