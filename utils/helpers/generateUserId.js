const User = require("../../models/User");

// Function to generate a sequential userId starting from 10000
const generateSequentialUserId = async () => {
  const startingUserId = 10000;

  // Find the highest userId in the database
  const lastUser = await User.findOne({}, { userId: 1 }) // Select only the `userId` field
    .sort({ userId: -1 }) // Sort by userId in descending order
    .exec();

  // If no users exist, start with the starting userId
  const newUserId = lastUser ? parseInt(lastUser.userId) + 1 : startingUserId;

  return newUserId.toString(); // Return as a string
};

module.exports = generateSequentialUserId;

// Function to generate a unique 5-digit userId
const generateUniqueUserId = async () => {
  let unique = false;
  let userId;

  while (!unique) {
    // Generate a random 5-digit number
    userId = Math.floor(10000 + Math.random() * 90000).toString();

    // Check if this userId already exists in the database
    const existingUser = await User.findOne({ userId });
    if (!existingUser) unique = true; // If not found, the ID is unique
  }

  return userId;
};

module.exports = generateUniqueUserId;
