const mongoose = require('mongoose');

const Schema = mongoose.Schema;

const marqueeSchema = new Schema({
  title: {
    type: String,
    required: true,
  },
  content: {
    type: String,
    required: true,
  },
  link: {
    type: String,
    required: true,
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
});

const Marquee = mongoose.model('Marquee', marqueeSchema);

module.exports = Marquee;
