const mongoose = require('mongoose');

const Listing = require('./listingModel');
const Coupon = require('./couponModel');
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
      min: [0, 'Discount can not be less than 0% off the initial price.'],
      max: [100, 'Discount can not be above 100% off the initial price.'],
      default: 0,
    },
    coupon: {
      type: mongoose.Schema.ObjectId,
      ref: 'Coupon',
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
    //Calculate total price of listings
    let totalListingsPrice = 0;

    for (const item of this.listings) {
      const listing = await Listing.findById(item._id);
      if (!listing) {
        return next(
          new AppError(`Listing with an id of ${item._id} not found`, 404)
        );
      }

      const variantsTotalPrice = item.variants.reduce(
        (acc, variant) => acc + +variant.price,
        0
      );
      const listingBasePrice =
        (+listing.price + +variantsTotalPrice) * item.amount;

      const itemDiscount = item.discount || 0; // Discount per item
      const discountedPrice = listingBasePrice * ((100 - itemDiscount) / 100);

      totalListingsPrice += discountedPrice;
    }

    // Calculate shipping price
    let shippingPrice = 0;
    const standardShippingPrice = +process.env.STANDARD_SHIPPING_PRICE || 5;
    const expressShippingPrice = +process.env.EXPRESS_SHIPPING_PRICE || 10;

    if (this.shippingOpt.shippingType === 'standard')
      shippingPrice = standardShippingPrice;
    if (this.shippingOpt.shippingType === 'express')
      shippingPrice = expressShippingPrice;

    // Apply coupon logic (if a coupon exists)
    let couponDiscount = 0;

    if (this.coupon) {
      const coupon = await Coupon.findById(this.coupon);

      if (!coupon || !coupon.isActive || coupon.expirationDate < new Date()) {
        return next(new AppError('Invalid or expired coupon.', 400));
      }

      if (coupon.minOrderValue > totalListingsPrice) {
        return next(
          new AppError(
            `Minimum order value for coupon is ${coupon.minOrderValue}.`,
            400
          )
        );
      }

      if (coupon.usageLimit && coupon.usedCount >= coupon.usageLimit) {
        return next(new AppError('Coupon usage limit reached.', 400));
      }

      // Validate applicable products
      if (coupon.applicableProducts.length > 0) {
        const applicableProducts = this.listings.filter((item) =>
          coupon.applicableProducts.includes(item._id)
        );
        if (applicableProducts.length === 0) {
          return next(
            new AppError(
              'No products in the invoice match the coupon requirements.',
              400
            )
          );
        }
      }

      // Validate applicable categories
      if (coupon.applicableCategories.length > 0) {
        const applicableCategories = this.listings.filter((item) =>
          coupon.applicableCategories.includes(item.category)
        );
        if (applicableCategories.length === 0) {
          return next(
            new AppError(
              'No categories in the invoice match the coupon requirements.',
              400
            )
          );
        }
      }

      // Calculate coupon discount
      if (coupon.discountType === 'percentage') {
        couponDiscount = (totalListingsPrice * coupon.discountValue) / 100;
      } else {
        couponDiscount = coupon.discountValue;
      }

      // Increment coupon usage count
      coupon.usedCount = (coupon.usedCount || 0) + 1;
      await coupon.save();
    }

    // Step 4: Calculate final total price
    this.totalPrice = (
      shippingPrice +
      totalListingsPrice -
      couponDiscount
    ).toFixed(2);

    next();
  } catch (error) {
    next(error);
  }
});

const Invoice = mongoose.model('Invoice', invoiceSchema);

module.exports = Invoice;
