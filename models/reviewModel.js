const mongoose = require('mongoose');
const Listing = require('./../models/listingModel');

const reviewSchema = new mongoose.Schema(
  {
    title: {
      type: String,
      required: [true, 'Areview must have a title.'],
      trim: true,
      maxLength: 100,
    },
    content: {
      type: String,
      required: [true, 'A review must have a review content.'],
    },
    rating: {
      type: Number,
      required: [true, 'A review must have rating.'],
      min: 1,
      max: 10,
      default: 0,
    },
    createdAt: {
      type: String,
      default: Date.now,
    },
    listing: {
      type: mongoose.Schema.ObjectId,
      ref: 'Listing',
      required: [true, 'Review must belog to listing'],
    },
    user: {
      type: mongoose.Schema.ObjectId,
      ref: 'User',
      required: [true, 'Review must belong to user.'],
    },
  },
  {
    toJSON: { virtuals: true },
    toObject: { virtuals: true },
  }
);

// restrict only ovly one review to a listing
reviewSchema.index({ listing: 1, user: 1 }, { unique: true });

reviewSchema.pre(/^find/, function (next) {
  this.populate({
    path: 'user',
    select: 'fullName photo',
  });

  next();
});

// Calculate averages functionality
reviewSchema.statics.calcAvgRatings = async function (listingId) {
  const stats = await this.aggregate([
    {
      $match: { listing: listingId },
    },
    {
      $group: {
        _id: '$listing',
        numRatings: { $sum: 1 },
        avgRating: { $avg: '$rating' },
      },
    },
  ]);

  if (stats.length > 0) {
    await Listing.findByIdAndUpdate(listingId, {
      ratingsAvg: stats[0].avgRating,
      numRatings: stats[0].numRatings,
    });
  } else {
    await Listing.findByIdAndUpdate(listingId, {
      ratingsAvg: 0,
      numRatings: 0,
    });
  }
};

// Persist the rating stats after creating the review
reviewSchema.post('save', function () {
  this.constructor.calcAvgRatings(this.listing);
});

// Calculate the ratings after editing or deleting a review
reviewSchema.post(/^findOneAnd/, async function (doc) {
  await doc.constructor.calcAvgRatings(doc.listing);
});

const Review = mongoose.model('Review', reviewSchema);

module.exports = Review;
