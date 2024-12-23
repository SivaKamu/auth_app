const express = require('express');
const { getAllUsers } = require('../controllers/userController');

const router = express.Router();

router.get('/getAllUser', getAllUsers);

module.exports = router;