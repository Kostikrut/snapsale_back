const Category = require('./../models/categoryModel');
const catchAsync = require('./../utils/catchAsync');
const AppError = require('../utils/appError');
const { uploadImage, getImageUrl } = require('../utils//S3ImageUpload');

exports.getCategories = catchAsync(async (req, res, next) => {
  const allCategories = await Category.find();
  const categories = [...allCategories[0].categories];

  for (const cat of categories) {
    const imageUrl = await getImageUrl(cat.imageName);
    cat.imageUrl = imageUrl;
  }

  res.status(200).json({
    status: 'success',
    data: { categories },
  });
});

exports.updateList = catchAsync(async (req, res, next) => {
  const findCategories = await Category.find();
  const categories = [...findCategories[0].categories];

  if (!req.body.category || typeof req.body.category !== 'string')
    return next(
      new AppError(
        "The 'category' property must be specified as a string to update the category list.",
        400
      )
    );

  if (!req.file) {
    return next(
      new AppError(
        "The 'image' property must be specified as a file to update the category list.",
        400
      )
    );
  }

  const hasCategoryProperty = categories.some(
    (cat) => cat.category === req.body.category.toLowerCase().trim()
  );

  if (hasCategoryProperty) {
    console.log('existing category');
    return next(
      new AppError(
        `A category with such name '${req.body.category}' already exists.`,
        400
      )
    );
  }

  const category = req.body.category.toLowerCase().trim();
  const imageName = await uploadImage(req.file);

  categories.push({ category, imageName });

  const updateCategories = await Category.findByIdAndUpdate(
    findCategories[0]._id,
    {
      categories,
    },
    { new: true }
  );

  res.status(201).json({
    status: 'success',
    data: { categories: updateCategories.categories },
  });
});

exports.deleteFromList = catchAsync(async (req, res, next) => {
  const findCategories = await Category.find();
  let categories = [...findCategories[0].categories];

  if (!req.body.category || typeof req.body.category !== 'string')
    return next(
      new AppError(
        "The 'category' property must be specified as a string to update the category list.",
        400
      )
    );

  const hasCategoryProperty = categories.some(
    (cat) => cat.category === req.body.category.toLowerCase().trim()
  );

  if (!hasCategoryProperty)
    return next(
      new AppError(
        `A category with such name '${req.body.category}' does't exists.`,
        400
      )
    );

  categories = categories.filter(
    (cat) => cat.category !== req.body.category.toLowerCase().trim()
  );

  const updateCategories = await Category.findByIdAndUpdate(
    findCategories[0]._id,
    {
      categories,
    },
    { new: true }
  );

  return res.status(200).json({
    status: 'success',
    message: `Category '${req.body.category
      .toLowerCase()
      .trim()}' was deleted from the list `,
    data: {
      categories: updateCategories.categories,
    },
  });
});
