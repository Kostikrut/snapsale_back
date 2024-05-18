const mongoose = require('mongoose');
const slugify = require('slugify');
const crypto = require('crypto');

const listingSchema = new mongoose.Schema(
  {
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
    images: [String],
    createdAt: {
      type: Date,
      default: Date.now(),
    },
    ratingsAvg: {
      type: Number,
      default: 0,
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
  }
);

// index the most queried fields
listingSchema.index({ price: 1, slug: 1 });

// Make a slug for the listing
listingSchema.pre('save', function (next) {
  this.slug = slugify(this.title, { lower: true });
  next();
});

// populate reviews for the current listing
listingSchema.virtual('reviews', {
  ref: 'Review',
  foreignField: 'listing',
  localField: '_id',
});

const Listing = mongoose.model('Listing', listingSchema);

module.exports = Listing;
