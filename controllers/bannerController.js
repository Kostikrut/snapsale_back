const catchAsync = require('../utils/catchAsync');
const Banner = require('../models/bannerModel');
const {
  uploadImage,
  getImageUrl,
  deleteImage,
} = require('../utils/S3ImageUpload');

exports.getAllBanners = catchAsync(async (req, res, next) => {
  let banners = await Banner.find();

  const updatedBanners = [];

  for (let banner of banners) {
    banner = banner.toObject();

    const imageUrl = await getImageUrl(banner.image.filename);

    banner.image.url = imageUrl;

    updatedBanners.push(banner);
  }

  res.status(200).json({
    status: 'success',
    results: banners.length,
    data: {
      banners: updatedBanners,
    },
  });
});

exports.getBanner = catchAsync(async (req, res, next) => {
  const banner = await Banner.findById(req.params.id);
  if (!banner) {
    return next(new AppError('No banner found with that ID', 404));
  }

  imageUrl = await getImageUrl(banner.image.filename);

  if (!imageUrl) {
    return next(new AppError('Failed to get image url', 400));
  }

  banner.image.url = imageUrl;

  res.status(200).json({
    status: 'success',
    data: {
      banner,
    },
  });
});

exports.createBanner = catchAsync(async (req, res, next) => {
  const { title, link, isActive } = req.body;

  const imageName = await uploadImage(req.file.buffer, 'banner');

  if (!imageName) {
    return next(new AppError('Failed to upload image', 400));
  }

  const image = { filename: imageName };

  const newBanner = await Banner.create({ title, image, link, isActive });

  res.status(201).json({
    status: 'success',
    data: {
      banner: newBanner,
    },
  });
});

exports.updateBanner = catchAsync(async (req, res, next) => {
  console.log(req.body, req.file);
  if (req.file) {
    const imageName = await uploadImage(req.file, 'banner');

    if (!imageName) {
      return next(new AppError('Failed to upload image', 400));
    }
    req.body.image = { filename: imageName };
  }

  const banner = await Banner.findByIdAndUpdate(req.params.id, req.body, {
    new: true,
    runValidators: true,
  });

  if (!banner) {
    return next(new AppError('No banner found with that id', 404));
  }
  res.status(200).json({
    status: 'success',
    data: {
      banner,
    },
  });
});

exports.deleteBanner = catchAsync(async (req, res, next) => {
  const banner = await Banner.findByIdAndDelete(req.params.id);

  if (!banner) {
    return next(new AppError('No banner found with that ID', 404));
  }

  await deleteImage(banner.image.filename);

  res.status(204).json({
    status: 'success',
    data: null,
  });
});
