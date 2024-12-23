  const mongoose = require('mongoose');
  
  const SymbolSchema = new mongoose.Schema({
    code: { type: String, required: true, unique: true },
    name: { type: String, required: true },
  });
  
  module.exports = mongoose.model('Symbol', SymbolSchema);
  