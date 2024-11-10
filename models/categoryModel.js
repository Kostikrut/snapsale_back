const mongoose = require('mongoose');

const categorySchema = new mongoose.Schema({
  categories: {
    type: [Object],
  },
});

const Category = mongoose.model('Category', categorySchema);

module.exports = Category;
