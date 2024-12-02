const mongoose = require('mongoose');
const slugify = require('slugify');

const listingSchema = new mongoose.Schema(
  {
    brand: {
      type: String,
      required: [true, 'A listing must have a brand'],
    },
    title: {
      type: String,
      trim: true,
      required: [true, 'A listing must have a title'],
    },
    slug: {
      type: String,
    },
    category: {
      type: String,
      required: [true, 'Listing must have a category'],
    },
    tags: [String],
    description: {
      type: String,
      trim: true,
    },
    price: {
      type: Number,
      required: [true, 'product must have a price'],
      min: 0,
    },
    discount: {
      type: Number,
      validate: {
        validator: function (val) {
          return val < this.price;
        },
        message: 'Discount price should be below the regular price',
      },
    },

    image: {
      filename: String,
    },
    variants: {
      type: [Object],
    },

    createdAt: {
      type: String,
      default: Date.now(),
    },
    ratingsAvg: {
      type: Number,
      default: 3,
      min: [1, 'Rating must be above 1'],
      max: [10, 'Rating must be blow 10'],
      set: (val) => Math.round(val * 10) / 10,
    },
    numRatings: {
      type: Number,
      default: 0,
    },
  },
  {
    toJSON: { virtuals: true },
    toObject: { virtuals: true },
    versionKey: false,
  }
);

listingSchema.index({ price: 1, slug: 1, title: 'text' });

listingSchema.pre('save', function (next) {
  this.slug = slugify(this.title, { lower: true });

  next();
});

listingSchema.virtual('reviews', {
  ref: 'Review',
  foreignField: 'listing',
  localField: '_id',
});

const Listing = mongoose.model('Listing', listingSchema);

module.exports = Listing;
