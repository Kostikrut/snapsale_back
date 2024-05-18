const mongoose = require('mongoose');

const invoiceSchema = new mongoose.Schema(
  {
    user: {
      type: mongoose.Schema.ObjectId,
      ref: 'User',
      required: [true, 'Invoice must belong to a user.'],
    },
    listings: {
      type: [mongoose.Schema.ObjectId],
      ref: 'Listing',
      required: [true, 'Invoice must have at least one listing.'],
    },
    totalPrice: {
      type: Number,
      default: 0,
      min: [0, 'price can not be less than 0.'],
    },
    discount: {
      type: Number,
      min: [0, 'Discount can not be less than 0.'],
      max: [1, 'Discount can not be above 1.'],
      default: 0,
    },
    currency: {
      type: String,
      enum: ['USD', 'EUR', 'ILS'],
      default: 'USD',
    },
    isPaid: {
      type: Boolean,
      default: false,
    },
    status: {
      type: String,
      enum: ['pending', 'canceled', 'rejected', 'approved'],
      default: 'pending',
    },
    createdAt: {
      type: Date,
      default: Date.now,
    },
  },
  {
    toJSON: { virtuals: true },
    toObject: { virtuals: true },
  }
);

// Calculate total price
invoiceSchema.post('save', async function (doc) {
  await doc
    .populate({
      path: 'listings',
      select: 'price title',
    })
    .execPopulate();

  const totalListingsPrice = doc.listings.reduce(
    (total, listing) => total + listing.price,
    0
  );

  doc.totalPrice = (
    totalListingsPrice -
    totalListingsPrice * doc.discount
  ).toFixed(2);

  await Invoice.updateOne({ _id: doc._id }, { totalPrice: doc.totalPrice });
});

const Invoice = mongoose.model('Invoice', invoiceSchema);

module.exports = Invoice;
