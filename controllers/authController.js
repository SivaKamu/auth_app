const User = require('../models/User');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const otpGenerator = require('otp-generator');
const sendOTPEmail = require('../utils/sendOTPEmail');

// Register User with OTP
exports.register = async (req, res) => {
  const { name, email, password } = req.body;

  try {
    // Check if user already exists
    let user = await User.findOne({ email });

    // If user exists but is not verified
    if (user && !user.isVerified) {

      const otp = otpGenerator.generate(6, { digits: true, upperCaseAlphabets: false, specialChars: false, lowerCaseAlphabets: false });
      const otpExpiresAt = new Date(Date.now() + 5 * 60 * 1000); // OTP valid for 5 minutes

      // Update existing user record
      user.name = name;
      user.password = await bcrypt.hash(password, 10);
      user.otp = otp;
      user.otpExpiresAt = otpExpiresAt;

      await user.save();

      sendOTPEmail(email, otp);

      return res.status(200).json({ message: 'OTP sent to your email address for verification' });
    }

    // If user exists and is already verified
    if (user && user.isVerified) {
      return res.status(400).json({ message: 'User is already registered and verified. Please log in.' });
    }

    // If user does not exist, create a new user
    const otp = otpGenerator.generate(6, { digits: true, upperCaseAlphabets: false, specialChars: false, lowerCaseAlphabets: false });
    const otpExpiresAt = new Date(Date.now() + 5 * 60 * 1000); // OTP valid for 5 minutes

    // Send OTP to user's email
    sendOTPEmail(email, otp);

    // Create a new user document
    const newUser = new User({
      name,
      email,
      password: await bcrypt.hash(password, 10), // Hash password
      otp,
      otpExpiresAt,
      isVerified: false, // Mark as not verified
    });

    await newUser.save();

    res.status(200).json({ message: 'OTP sent to your email address for verification' });
  } catch (error) {
    console.error('Error during registration:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
};


// Verify OTP for Registration
exports.verifyOTP = async (req, res) => {
  const { email, otp } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: 'User not found' });

    if (user.isVerified) {
      return res.status(400).json({ message: 'User is already verified' });
    }

    if (!user.otp || user.otp !== otp) {
      return res.status(400).json({ message: 'Invalid OTP' });
    }

    if (new Date() > user.otpExpiresAt) {
      return res.status(400).json({ message: 'OTP expired' });
    }

    // Mark user as verified
    user.otp = undefined;
    user.otpExpiresAt = undefined;
    user.isVerified = true; // Update verification status
    await user.save();

    res.status(200).json({ message: 'User verified successfully' });
  } catch (error) {
    console.error('Error during OTP verification:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
};

// Login User with OTP
exports.login = async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: 'Invalid credentials' });

    if (!user.isVerified) {
      return res.status(400).json({ message: 'Account is not verified. Please complete registration.' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: 'Invalid credentials' });

    // Generate OTP
    const otp = otpGenerator.generate(6, { digits: true, upperCaseAlphabets: false, lowerCaseAlphabets: false, specialChars: false });
    const otpExpiresAt = new Date(Date.now() + 5 * 60 * 1000); // OTP valid for 5 minutes

    // Send OTP to user's email
    sendOTPEmail(email, otp);

    // Save OTP and expiry time in user model
    user.otp = otp;
    user.otpExpiresAt = otpExpiresAt;
    await user.save();

    res.status(200).json({ message: 'OTP sent to your email address for login verification' });
  } catch (error) {
    console.error('Error during login:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
};

// Verify OTP for Login
exports.verifyLoginOTP = async (req, res) => {
  const { email, otp } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: 'Invalid credentials' });

    if (!user.otp || user.otp !== otp) {
      return res.status(400).json({ message: 'Invalid OTP' });
    }

    if (new Date() > user.otpExpiresAt) {
      return res.status(400).json({ message: 'OTP expired' });
    }

    // Clear OTP after successful login
    user.otp = undefined;
    user.otpExpiresAt = undefined;
    await user.save();

    // Generate JWT token
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });

    res.status(200).json({ token });
  } catch (error) {
    console.error('Error during OTP verification for login:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
};


exports.resendOTP = async (req, res) => {
  const { email } = req.body; // `type` can be 'signup' or 'login'

  try {
    // Find the user by email
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: 'User not found' });

    // Generate a new OTP
    const otp = otpGenerator.generate(6, {
      digits: true,
      upperCaseAlphabets: false,
      lowerCaseAlphabets: false,
      specialChars: false,
    });
    const otpExpiresAt = new Date(Date.now() + 5 * 60 * 1000); // OTP valid for 5 minutes

    // Update the user's OTP and expiry
    user.otp = otp;
    user.otpExpiresAt = otpExpiresAt;
    await user.save();

    // Send the new OTP via email
    sendOTPEmail(email, otp);

    res.status(200).json({ message: 'A new OTP has been sent to your email address' });
  } catch (error) {
    console.error('Error during OTP resend:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
};

//forgot password
exports.forgotPassword = async (req, res) => {
  const { email } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: "User with this email does not exist" });
    }

    // Generate OTP
    const otp = otpGenerator.generate(6, { digits: true, upperCaseAlphabets: false, lowerCaseAlphabets: false, specialChars: false });
    const otpExpiresAt = new Date(Date.now() + 5 * 60 * 1000); // OTP valid for 5 minutes

    // Update user record
    user.otp = otp;
    user.otpExpiresAt = otpExpiresAt;
    await user.save();

    // Send OTP via email
    sendOTPEmail(email, otp);

    res.status(200).json({ message: "OTP sent to your email address for password reset" });
  } catch (error) {
    console.error("Error during forgot password:", error);
    res.status(500).json({ message: "Server error", error: error.message });
  }
};

// Verify OTP
exports.verifyForgotPasswordOTP = async (req, res) => {
  const { email, otp } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: "User not found" });

    if (!user.otp || user.otp !== otp || new Date() > user.otpExpiresAt) {
      return res.status(400).json({ message: "Invalid or expired OTP" });
    }

    // Clear OTP after successful verification
    user.otp = undefined;
    user.otpExpiresAt = undefined;
    await user.save();

    res.status(200).json({ message: "OTP verified successfully. You can now reset your password" });
  } catch (error) {
    console.error("Error during OTP verification:", error);
    res.status(500).json({ message: "Server error", error: error.message });
  }
};

// Reset Password
exports.resetPassword = async (req, res) => {
  const { email, newPassword } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: "User not found" });

    // Hash the new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;

    // Clear any OTP data
    user.otp = undefined;
    user.otpExpiresAt = undefined;
    await user.save();

    res.status(200).json({ message: "Password reset successfully. You can now log in with your new password" });
  } catch (error) {
    console.error("Error during password reset:", error);
    res.status(500).json({ message: "Server error", error: error.message });
  }
};

