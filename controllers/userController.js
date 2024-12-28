const User = require('./../models/userModel');
const Invoice = require('./../models/invoiceModel');
const catchAsync = require('./../utils/catchAsync');
const AppError = require('./../utils/appError');
const factory = require('./handleFactory');
const { uploadImage, getImageUrl } = require('../utils//S3ImageUpload');

const filterObj = function (bodyObj, allowedFieldsArr) {
  const newBodyObj = {};

  Object.keys(bodyObj).forEach((el) => {
    if (allowedFieldsArr.includes(el)) newBodyObj[el] = bodyObj[el];
  });

  return newBodyObj;
};

exports.updateMe = catchAsync(async (req, res, next) => {
  let image;

  if (req.body.password || req.body.passwordConfirm)
    return next(
      new AppError(
        'This route is not for password update, please use /updateMyPassword.',
        400
      )
    );

  if (req.file) {
    const imageName = await uploadImage(req.file);
    if (!imageName)
      return next(
        new AppError(
          'Failed to upload image, please ensure the file is valid.',
          500
        )
      );
    image = { filename: imageName };
  }

  // 3) Filter out unwanted fields
  const filteredBody = filterObj(req.body, [
    'fullName',
    'email',
    'phone',
    'address',
  ]);

  // Add image only if it exists
  if (image) filteredBody.image = image;

  filteredBody.image = image;

  // 3) Update user doc
  const updatedUser = await User.findByIdAndUpdate(req.user._id, filteredBody, {
    new: true,
    runValidators: true,
  });

  res.status(200).json({
    status: 'success',
    user: updatedUser,
  });
});

// Deactivate user
exports.deleteMe = catchAsync(async (req, res, next) => {
  const user = await User.findByIdAndUpdate(req.user.id, { isActive: false });

  res.status(204).json({
    status: 'success',
  });
});

// Create users (Admin access only)
exports.createUser = catchAsync(async (req, res, next) => {
  const newUser = await User.create(req.body);

  if (!newUser)
    next(new AppError("Couldn't create user, please try again later.", 500));

  res.status(201).json({
    status: 'success',
    data: {
      user: {
        id: newUser.id,
        fullName: newUser.fullName,
        email: newUser.email,
        phone: newUser.phone,
        role: newUser.role,
      },
    },
  });
});

exports.getMe = (req, res, next) => {
  req.params.id = req.user.id;

  next();
};

exports.getPurchaseHistory = catchAsync(async (req, res, next) => {
  const userId = req.user._id;

  const purchases = await Invoice.find({
    user: userId,
    status: 'approved',
  })?.populate({
    path: 'listings',
    select: 'price title images',
  });

  if (!purchases) return next(new AppError('No purchases found.', 404));
  return res.status(200).json({
    status: 'success',
    data: { purchases },
  });
});

exports.getAllUsers = catchAsync(async (req, res, next) => {
  const filter = {};
  let users;

  if (req.query.fullName) {
    filter.fullName = { $regex: new RegExp(req.query.fullName, 'i') };
  }

  if (req.query.email) {
    filter.email = { $regex: new RegExp(req.query.email, 'i') };
  }

  if (req.query.phone) {
    filter.phone = req.query.phone;
  }

  if (req.user.role === 'admin') {
    users = await User.find(filter).select('-__v');
  } else {
    users = await User.find(filter)
      .select('-__v')
      .select('-isActive -passwordChangedAt');
  }

  for (let user of users) {
    if (user.image.filename) {
      user.image.url = await getImageUrl(user.image.filename);
    } else {
      user.image.url = await getImageUrl('placeholder_profile_picture.jpeg');
    }
  }

  return res.status(200).json({
    status: 'success',
    results: users.length,
    data: {
      users,
    },
  });
});

exports.updateUser = catchAsync(async (req, res, next) => {
  const { fullName, email, phone, role } = req.body;
  const updateObj = { fullName, email, phone, role };
  let image, imageName;

  if (req.file) {
    imageName = await uploadImage(req.file.buffer);
    image = { filename: imageName };
    updateObj.image = image;
  }

  const user = await User.findByIdAndUpdate(req.params.id, updateObj, {
    new: true,
    runValidators: true,
  });

  if (!user) {
    return next(new AppError('No document found with that Id', 404));
  }

  res.status(200).json({
    status: 'success',
    data: { user },
  });
});

exports.getUser = catchAsync(async (req, res, next) => {
  const user = await User.findById(req.params.id);

  if (!user) {
    return next(new AppError('No user found with that Id', 404));
  }

  user.image.url = await getImageUrl(user.image.filename);
  if (!user.image.url) {
    user.image.url = await getImageUrl('placeholder_profile_picture.jpeg');
  }

  res.status(200).json({
    status: 'success',
    data: {
      user,
    },
  });
});
exports.deleteUser = factory.deleteOne(User); // admin only or the user himself
