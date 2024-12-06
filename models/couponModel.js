const mongoose = require('mongoose');

const couponSchema = new mongoose.Schema(
  {
    code: {
      type: String,
      required: [true, 'Coupon code is required'],
      unique: true,
      trim: true,
    },
    discountType: {
      type: String,
      enum: ['percentage', 'fixed'],
      required: [true, 'Discount type is required ("percentage" or "fixed")'],
    },
    discountValue: {
      type: Number,
      required: [true, 'Discount value is required'],
    },
    expirationDate: {
      type: Date,
      required: [true, 'Expiration date is required'],
    },
    usageLimit: {
      type: Number,
      default: null,
    },
    usedCount: {
      type: Number,
      default: 0,
    },
    minOrderValue: {
      type: Number,
      default: 0,
    },
    applicableCategories: {
      type: [String],
      default: [],
    },
    applicableProducts: [
      {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Listing',
        default: [],
      },
    ],
    isActive: {
      type: Boolean,
      default: true,
    },
    createdBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: [true, 'Coupon creator is required'],
    },
  },
  {
    timestamps: true,
  }
);

couponSchema.methods.isValid = async function (invoice) {
  const now = new Date();

  if (!this.isActive || this.expirationDate <= now) {
    return {
      valid: false,
      message: 'This coupon is not active or has expired.',
    };
  }

  if (invoice.total < this.minOrderValue) {
    return {
      valid: false,
      message: `The total price does not meet the minimum order value of ${this.minOrderValue}.`,
    };
  }

  if (this.usageLimit && this.usedCount >= this.usageLimit) {
    return {
      valid: false,
      message: 'The coupon has reached its usage limit.',
    };
  }

  if (this.applicableProducts.length > 0) {
    const applicableProducts = invoice.listings.filter((listing) =>
      this.applicableProducts.includes(listing.product)
    );

    if (applicableProducts.length === 0) {
      return {
        valid: false,
        message: 'No products in the invoice match the coupon requirements.',
      };
    }
  }

  if (this.applicableCategories.length > 0) {
    const applicableCategories = invoice.listings.filter((listing) =>
      this.applicableCategories.includes(listing.category)
    );

    if (applicableCategories.length === 0) {
      return {
        valid: false,
        message: 'No categories in the invoice match the coupon requirements.',
      };
    }
  }

  return { valid: true };
};

const Coupon = mongoose.model('Coupon', couponSchema);

module.exports = Coupon;
