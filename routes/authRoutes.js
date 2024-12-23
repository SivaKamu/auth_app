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
  logout,
  stockData,
  fundamentalData,
  cryptocurrencyData,
  currencyExchangeData,
  populateMarkets,
  getMarkets,
  populateSymbols,
  getSymbols
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

router.get('/stockData/:timeSeries/:symbol', stockData);

router.get('/fundamentalData/:timeSeries/:symbol', fundamentalData);

router.get('/cryptocurrencyData/:timeSeries/:symbol/:market', cryptocurrencyData);

router.get('/currencyExchangeData/:fromCurrency/:toCurrency', currencyExchangeData);

router.get('/populateMarkets', populateMarkets);

router.get('/getMarkets', getMarkets);

router.get('/populateSymbols', populateSymbols);

router.get('/getSymbols', getSymbols);

// Example protected route
router.get('/profile', protect, (req, res) => {
  res.status(200).json({ message: 'This is a protected route', userId: req.user.id });
});

module.exports = router;
 