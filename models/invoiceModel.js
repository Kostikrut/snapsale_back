const mongoose = require('mongoose');

const Listing = require('./listingModel');
const AppError = require('../utils/appError');

const invoiceSchema = new mongoose.Schema(
  {
    user: {
      type: mongoose.Schema.ObjectId,
      ref: 'User',
      // required: [true, 'Invoice must belong to a user.'],
    },
    guestInfo: {
      fullName: {
        type: String,
        required: [
          function () {
            return !this.user;
          },
          'Full name is required for guest checkout.',
        ],
      },
      phone: {
        type: String,
        required: [
          function () {
            return !this.user;
          },
          'Phone number is required for guest checkout.',
        ],
      },
      email: {
        type: String,
        required: [
          function () {
            return !this.user;
          },
          'Email is required for guest checkout.',
        ],
      },
    },
    listings: {
      type: Array,
      ref: 'Listing',
      required: [true, 'Invoice must have at least one listing.'],
    },
    shippingOpt: {
      shippingType: {
        type: String,
        enum: ['standard', 'express', 'store'],
      },
      address: {
        type: String,
      },
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
      enum: ['pending', 'canceled', 'complete'],
      default: 'pending',
    },
    reviewLeft: {
      type: [mongoose.Schema.ObjectId],
      ref: 'Listing',
    },
    createdAt: {
      type: Date,
      default: Date.now,
    },
    checkoutSessionId: String,
  },

  {
    toJSON: { virtuals: true },
    toObject: { virtuals: true },
  }
);

// Calculate total price
invoiceSchema.pre('save', async function (next) {
  try {
    let totalListingsPrice = 0;

    for (const item of this.listings) {
      const listing = await Listing.findById(item._id);
      if (!listing) {
        return next(
          new AppError(`Listing with an id of ${item.listingId} not found`, 404)
        );
      }

      const variantsTotalPrice = item.variants.reduce((acc, variant) => {
        return acc + Number(variant.price);
      }, 0);

      const listingTotalPrice =
        (Number(listing.price) + Number(variantsTotalPrice)) * item.amount;

      totalListingsPrice += listingTotalPrice;
    }

    let shippingPrice = 0;
    const standardShippingPrice =
      Number(process.env.STANDARD_SHIPPING_PRICE) || 5;
    const expressShippingPrice = Number(
      process.env.EXPRESS_SHIPPING_PRICE || 10
    );

    if (this.shippingOpt.shippingType === 'standard')
      shippingPrice = standardShippingPrice;
    if (this.shippingOpt.shippingType === 'express')
      shippingPrice = expressShippingPrice;

    this.totalPrice = (
      shippingPrice +
      totalListingsPrice -
      totalListingsPrice * this.discount
    ).toFixed(2);

    next();
  } catch (error) {
    next(error);
  }
});

const Invoice = mongoose.model('Invoice', invoiceSchema);

module.exports = Invoice;
