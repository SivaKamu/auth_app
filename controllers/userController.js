const User = require('../models/User');

// Get all users
exports.getAllUsers = async (req, res) => {
    try {
      const users = await User.find().select("name email isVerified userId -_id");

      res.status(200).json( { message: 'Success', statusCode:200, users });
    } catch (error) {
      console.error("Error fetching users:", error);
      res.status(500).json({ message: "Server error", error: error.message });
    }
  };