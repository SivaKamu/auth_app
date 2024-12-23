require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const connectDB = require('./config/db');
const authRoutes = require('./routes/authRoutes');
const userRoutes = require('./routes/userRoutes');
const axios = require('axios');


const app = express();

// Connect to Database
connectDB();

// Route to fetch stock data
app.get('/stock/:symbol', async (req, res) => {
  const symbol = req.params.symbol;
  try {
      const response = await axios.get(ALPHA_VANTAGE_URL, {
          params: {
              function: 'TIME_SERIES_DAILY',
              symbol: symbol,
              apikey: API_KEY
          }
      });
      const data = response.data;
      // Check for errors in the API response
      if (data['Error Message']) {
          return res.status(404).json({ error: 'Stock symbol not found' });
      }
      res.json(data);
  } catch (error) {
      console.error(error);
      res.status(500).json({ error: 'Error fetching stock data' });
  }
});

// Middleware
app.use(cors());
app.use(bodyParser.json());

// Routes
app.use('/api/auth', authRoutes);
app.use('/api/user', userRoutes)

const PORT = process.env.PORT;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
