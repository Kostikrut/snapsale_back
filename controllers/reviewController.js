const Review = require('./../models/reviewModel');
const Invoice = require('./../models/invoiceModel');
const factory = require('./../controllers/handleFactory');
const catchAsync = require('../utils/catchAsync');

exports.getListingUserIds = (req, res, next) => {
  //Aloow nested routes
  req.body.listing = req.params.listingId;
  req.body.user = req.user.id;

  next();
};

// exports.createReview = catchAsync(async (req, res, next) => {
//   const purchases = await Invoice.find({
//     user: userId,
//     status: 'approved',
//   })?.populate({
//     path: 'listings',
//     select: 'id',
//   });

//   return res.status(401).json({
//     status: 'fail',
//     message:
//       'Unauthorized, you must purchase the product before leaving a review.',
//   });
// });

exports.createReview = factory.createOne(Review);
exports.getAllReviews = factory.getAll(Review);
exports.getReview = factory.getOne(Review);
exports.updateReview = factory.updateOne(Review);
exports.deleteReview = factory.deleteOne(Review);
