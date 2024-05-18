const { query } = require('express');
const Listing = require('./../models/listingModel');
const catchAsync = require('./../utils/catchAsync');
const AppError = require('../utils/appError');
const factory = require('./handleFactory');

exports.getListing = catchAsync(async (req, res, next) => {
  const listing = await Listing.findById(req.params.id).populate('reviews');

  if (!listing) return next(new AppError('No listing found with that id.'));

  res.status(200).json({
    status: 'success',
    data: { listing },
  });
});

exports.getAllListings = factory.getAll(Listing);
exports.getListing = factory.getOne(Listing, { path: 'reviews' });
exports.createListing = factory.createOne(Listing);
exports.updateListing = factory.updateOne(Listing);
exports.deleteListing = factory.deleteOne(Listing);
