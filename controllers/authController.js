const User = require('../models/User');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const otpGenerator = require('otp-generator');
const sendOTPEmail = require('../utils/sendOTPEmail');
const sendResetLinkEmail = require('../utils/sendResetLinkEmail');
const generateSequentialUserId = require("../utils/helpers/generateUserId");


// Generate a reset token
const generateResetToken = (userId) => {
  return jwt.sign({ id: userId }, process.env.JWT_RESET_PASSWORD_SECRET, { expiresIn: '15m' });
};


// Register User with OTP
exports.register = async (req, res) => {
  const { name, email, password } = req.body;

  console.log(req.body, "sample");

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

      sendOTPEmail(email, otp, userId);

      return res.status(200).json({ message: 'OTP sent to your email address for verification only', statusCode:200 });
    }

    // If user exists and is already verified
    if (user && user.isVerified) {
      return res.status(409).json({ message: 'User is already registered and verified. Please log in.',  statusCode:409 });
    }

    // If user does not exist, create a new user
    const otp = otpGenerator.generate(6, { digits: true, upperCaseAlphabets: false, specialChars: false, lowerCaseAlphabets: false });
    const otpExpiresAt = new Date(Date.now() + 5 * 60 * 1000); // OTP valid for 5 minutes

    const userId = await generateSequentialUserId();

    // Send OTP to user's email
    sendOTPEmail(email, otp, userId);

    // Create a new user document
    const newUser = new User({
      name,
      email,
      password: await bcrypt.hash(password, 10), // Hash password
      userId,
      otp,
      otpExpiresAt,
      isVerified: false, // Mark as not verified
    });

    await newUser.save();

    res.status(200).json({ message: 'OTP sent to your email address for verification', statusCode:200 });
  } catch (error) {
    console.error('Error during registration:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
};

// Login User with OTP
exports.login = async (req, res) => {
  const { email, password } = req.body;
  console.log(req.body);
  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: 'Invalid credentials', statusCode:409 });

    if (!user.isVerified) {
      return res.status(400).json({ message: 'Account is not verified. Please complete registration.', statusCode:409 });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: 'Password Wrong', statusCode:409 });

    // Generate OTP
    const otp = otpGenerator.generate(6, { digits: true, upperCaseAlphabets: false, lowerCaseAlphabets: false, specialChars: false });
    const otpExpiresAt = new Date(Date.now() + 5 * 60 * 1000); // OTP valid for 5 minutes

    // Send OTP to user's email
    sendOTPEmail(email, otp, user.userId);

    // Save OTP and expiry time in user model
    user.otp = otp;
    user.otpExpiresAt = otpExpiresAt;
    await user.save();

    res.status(200).json({ message: 'OTP sent to your email address for login verification', statusCode:200 });
  } catch (error) {
    console.error('Error during login:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
};


// Verify OTP
exports.verifyOTP = async (req, res) => {
  const { email, otp, type } = req.body; // Type can be 'signup', 'login', or 'forgot-password'

  try {
    // Validate type
    if (!["signup", "login", "forgot-password"].includes(type)) {
      return res.status(400).json({ message: "Invalid type", statusCode:409 });
    }

    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: "User not found", statusCode:409 });

    if (!user.otp || user.otp !== otp || new Date() > user.otpExpiresAt) {
      return res.status(400).json({ message: "Invalid or expired OTP", statusCode:409 });
    }

    // Clear OTP after successful verification
    user.otp = undefined;
    user.otpExpiresAt = undefined;

    // Handle signup-specific verification
    if (type === "signup") {
      user.isVerified = true; // Mark user as verified
      await user.save();
      return res.status(200).json({ message: "User verified successfully. You can now log in.", statusCode:200 });
    }

    // Handle login-specific verification
    if (type === "login") {
      // Generate JWT token after login
      const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: "5m" });

      //refresh token
      const refreshToken = jwt.sign({ id: user._id }, process.env.JWT_REFRESH_SECRET, { expiresIn: '7d' });
    
      user.refreshToken = refreshToken;

      await user.save();
      return res.status(200).json({ message: "Login successful", token, refreshToken, statusCode:200 });
    }

    // Handle forgot-password-specific verification
    if (type === "forgot-password") {
      await user.save();
      return res.status(200).json({ message: "OTP verified successfully. You can now reset your password", statusCode:200 });
    }
  } catch (error) {
    console.error("Error during OTP verification:", error);
    res.status(500).json({ message: "Server error", error: error.message });
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
    sendOTPEmail(email, otp, user.userId);

    res.status(200).json({ message: 'A new OTP has been sent to your email address' });
  } catch (error) {
    console.error('Error during OTP resend:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
};

//forgot password
exports.forgotPasswordOld = async (req, res) => {
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
    sendOTPEmail(email, otp, user.userId);

    res.status(200).json({ message: "OTP sent to your email address for password reset" });
  } catch (error) {
    console.error("Error during forgot password:", error);
    res.status(500).json({ message: "Server error", error: error.message });
  }
};

// Forgot Password: Send Reset Link
exports.forgotPassword = async (req, res) => {
  const { email } = req.body;

  try {
    // Find user by email
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: "User with this email does not exist", statusCode: 409 });
    }

    // Generate a reset token
    const resetToken = generateResetToken(user._id);

    // Send email with reset link
    const resetLink = `${process.env.FRONTEND_URL}/resetPassword/${resetToken}`;

    // Send OTP via email
    sendResetLinkEmail(email, resetLink, user.userId);

    res.status(200).json({ message: "Password reset link sent to your email.", statusCode: 200 });
  } catch (error) {
    console.error("Error during forgot password:", error);
    res.status(500).json({ message: "Server error", error: error.message });
  }
};

// Reset Password
exports.resetPasswordOld = async (req, res) => {
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

// Reset Password: Update Password
exports.resetPassword = async (req, res) => {
  const { token, newPassword } = req.body;
  console.log(req.body,"request");
  try {
    // Verify the reset token
    const decoded = jwt.verify(token, process.env.JWT_RESET_PASSWORD_SECRET);
    const userId = decoded.id;
    console.log(decoded,"request");
    // Find user by decoded ID
    const user = await User.findById(userId);
    if (!user) return res.status(404).json({ message: "User not found", statusCode: 409 });

    // Hash the new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // Update user's password
    user.password = hashedPassword;
    await user.save();

    res.status(200).json({ message: "Password reset successfully. You can now log in with your new password.", statusCode: 200});
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      return res.status(400).json({ message: "Reset link has expired. Please request a new one.", statusCode: 409 });
    }
    console.error("Error during password reset:", error);
    res.status(500).json({ message: "Server error", error: error.message });
  }
};


// Refresh Token API
exports.refreshToken = async (req, res) => {
  const { refreshToken } = req.body;

  if (!refreshToken) {
    return res.status(400).json({ message: 'Refresh token is required' });
  }

  try {
    const user = await User.findOne({ refreshToken });
    if (!user) {
      return res.status(403).json({ message: 'Invalid refresh token' });
    }

    // Verify the refresh token
    jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET, async (err, decoded) => {
      if (err) {
        return res.status(403).json({ message: 'Invalid or expired refresh token' });
      }

      // Generate a new access token
      const newAccessToken = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '5m' });

      // Optionally, generate a new refresh token if you want to rotate refresh tokens
      // const newRefreshToken = jwt.sign({ id: user._id }, process.env.JWT_REFRESH_SECRET, { expiresIn: '7d' });
      // user.refreshToken = newRefreshToken;
      // await user.save();

      res.status(200).json({ accessToken: newAccessToken });
    });
  } catch (error) {
    console.error('Error during refresh token:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
};

// Logout
exports.logout = async (req, res) => {
  const { refreshToken } = req.body;

  if (!refreshToken) {
    return res.status(400).json({ message: 'Refresh token is required' });
  }

  try {
    // Find the user by their refresh token
    const user = await User.findOne({ refreshToken });
    if (!user) {
      return res.status(404).json({ message: 'User not found or invalid refresh token' });
    }

    // Remove the refresh token from the user
    user.refreshToken = null;
    await user.save();

    res.status(200).json({ message: 'Logged out successfully' });
  } catch (error) {
    console.error('Error during logout:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
};

