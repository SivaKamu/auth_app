const nodemailer = require('nodemailer');

// Function to send OTP email
const sendOTPEmail = async (email, otp) => {
  try {
    // Create a transporter with SMTP settings
    const transporter = nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: process.env.SMTP_PORT,
      secure: process.env.SMTP_PORT === "465", // Secure connection for port 465
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS,
      },
    });

    // Email options
    const mailOptions = {
      from: `"No Reply" <${process.env.SMTP_USER}>`, // Custom "from" name
      to: email,
      subject: 'Your OTP Code',
      text: `Hello,\n\nYour OTP code is: ${otp}\n\nThis code will expire in 5 minutes.\n\nThank you!`,
    };

    // Send email
    const info = await transporter.sendMail(mailOptions);
    console.log('OTP email sent:', info.response);
    return { success: true, message: 'OTP sent successfully.' };
  } catch (error) {
    console.error('Error sending OTP email:', error);
    return { success: false, message: 'Failed to send OTP.', error: error.message };
  }
};

module.exports = sendOTPEmail;
