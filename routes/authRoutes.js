const express = require('express');
const {
  register,
  login,
  verifyOTP,
  verifyLoginOTP,
  resendOTP,
  forgotPassword,
  verifyForgotPasswordOTP,
  resetPassword,
  refreshToken,
  logout
} = require('../controllers/authController');
const { protect } = require('../middleware/authMiddleware');

const router = express.Router();

// Register routes
router.post('/signup', register);
router.post('/verify-otp', verifyOTP);
router.post('/login', login);
// router.post('/verify-login-otp', verifyLoginOTP);
router.post('/resend-otp', resendOTP);
router.post('/forgot-password', forgotPassword);
// router.post('/forgot-password-otp', verifyForgotPasswordOTP);
router.post('/reset-password', resetPassword);

router.post('/refresh-token', refreshToken);

router.post('/logout', logout);

// Example protected route
router.get('/profile', protect, (req, res) => {
  res.status(200).json({ message: 'This is a protected route', userId: req.user.id });
});

module.exports = router;
 