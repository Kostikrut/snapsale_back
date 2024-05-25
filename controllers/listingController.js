const multer = require('multer');
const path = require('path');
const Listing = require('./../models/listingModel');
const catchAsync = require('./../utils/catchAsync');
const AppError = require('../utils/appError');
const factory = require('./handleFactory');

// Set up multer storage
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + path.extname(file.originalname));
  },
});

// Multer filter to ensure only image files are uploaded
const fileFilter = (req, file, cb) => {
  if (file.mimetype.startsWith('image')) {
    cb(null, true);
  } else {
    cb(new AppError('Not an image! Please upload only images.', 400), false);
  }
};

const upload = multer({
  storage,
  fileFilter,
});

exports.uploadListingImage = upload.single('image');

exports.createListing = catchAsync(async (req, res) => {
  const { title, description, category, tags, price } = req.body;
  let image = null;

  if (req.file) {
    image = {
      filename: req.file.filename,
      url: `/uploads/${req.file.filename}`,
    };
  }

  const listing = await Listing.create({
    title,
    tags,
    category,
    description,
    price,
    image,
  });

  res.status(201).json({
    status: 'success',
    data: { listing },
  });
});

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
// exports.createListing = factory.createOne(Listing);
exports.updateListing = factory.updateOne(Listing);
exports.deleteListing = factory.deleteOne(Listing);
