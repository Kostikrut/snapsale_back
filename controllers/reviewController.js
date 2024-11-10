const mongoose = require('mongoose');

const Review = require('./../models/reviewModel');
const Invoice = require('./../models/invoiceModel');
const factory = require('./../controllers/handleFactory');
const catchAsync = require('../utils/catchAsync');
const AppError = require('../utils/appError');

exports.getListingUserIds = (req, res, next) => {
  req.body.listing = req.params.listingId;
  req.body.user = req.user.id;

  next();
};

exports.isUserLeftReview = catchAsync(async (req, res, next) => {
  const invoices = await Invoice.find({
    user: req.body.user,
    isPaid: true,
    status: 'complete',
    listings: {
      $elemMatch: { id: req.body.listing },
    },
  });

  if (
    !invoices.length ||
    invoices.filter((invoice) => invoice._id === req.body.invoiceId).length
  ) {
    return next(
      new AppError(
        'You must to pay and complete the order to be able to leave a review.',
        404
      )
    );
  }

  const reviews = invoices.filter((invoice) =>
    invoice.reviewLeft.includes(req.body.listing)
  );

  if (reviews.length) {
    return res.status(403).json({
      status: 'error',
      message: 'You already left a review to this product.',
    });
  }

  next();
});

exports.createReview = catchAsync(async (req, res, next) => {
  const review = await Review.create(req.body);

  if (!review)
    return next(
      new AppError(
        'Please fill all the fields (title, content and rating) and try again.',
        400
      )
    );

  await Invoice.findByIdAndUpdate(
    req.body.invoice,
    { $push: { reviewLeft: req.body.listing } },
    { new: true, useFindAndModify: false }
  );

  return res.status(200).json({
    status: 'success',
    data: review,
  });
});

exports.getAllReviews = factory.getAll(Review);
exports.getReview = factory.getOne(Review);
exports.updateReview = factory.updateOne(Review);
exports.deleteReview = factory.deleteOne(Review);
