const Listing = require('./../models/listingModel');
const Category = require('./../models/categoryModel');
const catchAsync = require('./../utils/catchAsync');
const AppError = require('../utils/appError');
const factory = require('./handleFactory');
const apiFeatures = require('../utils/apiFeatures');
const {
  uploadImage,
  getImageUrl,
  deleteImage,
} = require('../utils/S3ImageUpload');

exports.createListing = catchAsync(async (req, res, next) => {
  const { title, description, category, tags, price, brand, year } = req.body;
  const parsedTags = typeof tags === 'string' ? JSON.parse(tags) : tags;

  const imageName = await uploadImage(req.file);

  if (!imageName)
    return next(
      new AppError(
        'Failed to upload an image, please make sure that the file is an image.',
        500
      )
    );

  const image = { filename: imageName };

  const listing = await Listing.create({
    title,
    tags: parsedTags,
    category,
    description,
    price,
    image,
    brand,
    year,
  });

  res.status(201).json({
    status: 'success',
    data: { listing },
  });
});

exports.updateListing = catchAsync(async (req, res) => {
  console.log('enter');
  const { title, description, category, tags, price, discount, brand, year } =
    req.body;
  const parsedTags = typeof tags === 'string' ? JSON.parse(tags) : tags;
  let image, imageName;
  let updateObj = {
    brand,
    year,
    title,
    tags: parsedTags,
    category,
    description,
    price,
    discount,
  };

  updateObj = Object.entries(updateObj)
    .filter(([key, value]) => value !== undefined && value !== '')
    .reduce((acc, [key, value]) => {
      acc[key] = value;
      return acc;
    }, {});

  if (req.file) {
    imageName = await uploadImage(req.file);
    image = { filename: imageName };
    updateObj.image = image;
  }

  const listing = await Listing.findByIdAndUpdate(req.params.id, updateObj, {
    new: true,
  });

  res.status(201).json({
    status: 'success',
    data: { listing },
  });
});

exports.updateListingVariant = catchAsync(async (req, res, next) => {
  const { name, type, stock = 0, price = 0 } = req.body;
  const updateObj = {};

  if (!name || !type) {
    return next(
      new AppError(
        'Please provide the name, type, and stock for the variant.',
        400
      )
    );
  }

  const listing = await Listing.findById(req.params.id);

  if (!listing) {
    return next(new AppError('No listing found with that id.', 404));
  }

  const existingImgName = listing.variants.find(
    (variant) => variant.type === type && variant.name === name
  )?.image?.filename;

  updateObj.image = { filename: '' };

  if (req.file) {
    const imageName = await uploadImage(req.file);
    const image = { filename: imageName };
    updateObj.image = image;
  }

  if (existingImgName) {
    updateObj.image = { filename: existingImgName };
  }

  updateObj.type = type;
  updateObj.name = name;
  updateObj.stock = stock;
  updateObj.price = price;

  const filteredListing = listing.variants.filter(
    (variant) =>
      !(variant.type === updateObj.type && variant.name === updateObj.name)
  );

  filteredListing.push(updateObj);

  listing.variants = filteredListing;

  const newListing = await Listing.findByIdAndUpdate(req.params.id, listing, {
    new: true,
    runValidators: true,
  });

  if (!newListing) {
    return next(
      new AppError(
        "Couldn't update listing variant, please try again later",
        500
      )
    );
  }

  res.status(200).json({
    status: 'success',
    data: {
      listing: newListing,
    },
  });
});

exports.getListing = catchAsync(async (req, res, next) => {
  let listing = await Listing.findById(req.params.id).populate('reviews');

  Listing.findM;

  if (!listing)
    return next(new AppError('No listing found with that id.', 404));

  listing = listing.toObject();

  const imageUrl = await getImageUrl(listing.image.filename);
  listing.image.url = imageUrl;

  for (const variant of listing.variants) {
    const variantImageUrl = await getImageUrl(variant.image.filename);
    variant.image.url = variantImageUrl;
  }

  res.status(200).json({
    status: 'success',
    data: { listing },
  });
});

exports.getAllListings = catchAsync(async (req, res, next) => {
  const totalListings = await Listing.countDocuments();

  const limit = parseInt(req.query.limit, 10) || 20;
  const page = parseInt(req.query.page, 10) || 1;

  // Setup query features
  const queryFeatures = new apiFeatures(
    Listing.find().select('-__v'),
    req.query
  )
    .filter()
    .paginate()
    .limit()
    .sort();

  const listings = await queryFeatures.query;

  if (!listings.length) {
    return next(new AppError('Requested listings not found.', 404));
  }

  const isLastPage = listings.length < limit || page * limit >= totalListings;

  const updatedListings = [];

  for (let listing of listings) {
    listing = listing.toObject();

    const imageUrl = await getImageUrl(listing.image.filename);
    listing.image.url = imageUrl;

    for (const variant of listing.variants) {
      const imageUrl = await getImageUrl(variant.image.filename);
      variant.image.url = imageUrl;
    }

    updatedListings.push(listing);
  }

  return res.status(200).json({
    status: 'success',
    results: updatedListings.length,
    isLastPage,
    data: updatedListings,
  });
});

exports.getThreeListingsByCategory = catchAsync(async (req, res, next) => {
  const categoriesList = await Category.find();
  if (!categoriesList)
    return next(
      new AppError("Coudn't fetch categories, Please try againe later.", 500)
    );

  const categories = categoriesList.at(0).categories.map((cat) => cat.category);

  const listingsByCategory = await Listing.aggregate([
    {
      $match: {
        category: { $in: categories },
      },
    },
    {
      $group: {
        _id: '$category',
        listings: { $push: '$$ROOT' },
      },
    },
    {
      $project: {
        listings: { $slice: ['$listings', 3] },
      },
    },
  ]);

  // Add imageURL to each listing
  for (const obj of listingsByCategory) {
    for (const listing of obj.listings) {
      if (listing.image && listing.image.filename) {
        listing.image.imageUrl = await getImageUrl(listing.image.filename);
      }
    }
  }

  res.status(200).json({
    status: 'success',
    data: listingsByCategory,
  });
});

exports.getSearchedListings = catchAsync(async (req, res, next) => {
  if (!req.query.title)
    return next(
      new AppError(
        'Search query has not provided, please provide a query to complete this action.',
        400
      )
    );

  const searchRegex = new RegExp(req.query.title, 'i');

  const listings = await Listing.find({
    $or: [
      { title: { $regex: searchRegex } },
      { brand: { $regex: searchRegex } },
    ],
  });

  if (!listings.length > 0)
    return next(
      new AppError('No listings found for the provided search query.', 404)
    );

  const updatedListings = [];

  for (let listing of listings) {
    listing = listing.toObject();

    const imageUrl = await getImageUrl(listing.image.filename);
    listing.image.url = imageUrl;

    for (const variant of listing.variants) {
      const imageUrl = await getImageUrl(variant.image.filename);
      variant.image.url = imageUrl;
    }

    updatedListings.push(listing);
  }

  return res.status(200).json({
    status: 'success',
    results: updatedListings.length,
    data: updatedListings,
  });
});

exports.getListingImgUrl = catchAsync(async (req, res, next) => {
  const listing = await Listing.findById(req.params.id);

  if (!listing)
    return next(
      new AppError(`No listing found with an id of '${req.params.id}'.`, 404)
    );

  let imageUrl = await getImageUrl(listing.image.filename);
  if (!imageUrl) imageUrl = '';

  res.status(200).json({
    status: 'success',
    data: { imageUrl },
  });
});

exports.getImagesUrls = catchAsync(async (req, res) => {
  const { images } = req.body;
  let urls = [];

  for (const image of images) {
    const imageUrl = await getImageUrl(image);
    urls.push(imageUrl);
  }

  res.status(200).json({
    status: 'success',
    data: urls,
  });
});

exports.deleteListing = catchAsync(async (req, res, next) => {
  const listing = await Listing.findById(req.params.id);
  const imageName = listing.image.filename;

  const doc = await Listing.findByIdAndDelete(req.params.id);

  if (!doc) {
    return next(new AppError('No listing found with that id.', 404));
  }

  await deleteImage(imageName);

  res.status(204).json({});
});
