const mongoose = require('mongoose');

const StockDataSchema = new mongoose.Schema({
    symbol: { type: String, required: true },
    data: { type: Object, required: true },
    fetchedAt: { type: Date, default: Date.now },
});

module.exports = mongoose.model('StockData', StockDataSchema);
