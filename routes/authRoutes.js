const express = require('express');
const { register, login, verifyOTP, verifyLoginOTP, resendOTP } = require('../controllers/authController');
const { protect } = require('../middleware/authMiddleware');

const router = express.Router();

// Register routes
router.post('/signup', register);
router.post('/verify-signup-otp', verifyOTP);
router.post('/login', login);
router.post('/verify-login-otp', verifyLoginOTP);
router.post('/resend-otp', resendOTP);

// Example protected route
router.get('/profile', protect, (req, res) => {
  res.status(200).json({ message: 'This is a protected route', userId: req.user.id });
});

module.exports = router;
