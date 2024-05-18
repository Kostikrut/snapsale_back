const User = require('./../models/userModel');
const Invoice = require('./../models/invoiceModel');
const catchAsync = require('./../utils/catchAsync');
const AppError = require('./../utils/appError');
// const createSendToken = require('./../controllers/authController');
const factory = require('./handleFactory');

const filterObj = function (bodyObj, allowedFieldsArr) {
  const newBodyObj = {};

  Object.keys(bodyObj).forEach((el) => {
    if (allowedFieldsArr.includes(el)) newBodyObj[el] = bodyObj[el];
  });

  return newBodyObj;
};

exports.updateMe = catchAsync(async (req, res, next) => {
  // 1) Create an error if user posts password data
  if (req.body.password || req.body.passwordConfirm)
    return next(
      new AppError(
        'This route is not for password update, please use /updateMyPassword.',
        400
      )
    );

  // 2) Filter out unwanted fields
  const filteredBody = filterObj(req.body, [
    'fullName',
    'email',
    'phone',
    'location',
  ]);

  // 3) Update user doc
  const updatedUser = await User.findByIdAndUpdate(req.user.id, filteredBody, {
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

exports.getPurchaseHistory = catchAsync(async (req, res) => {
  const userId = req.user._id;

  const purchases = await Invoice.find({
    user: userId,
    status: 'approved',
  })?.populate({
    path: 'listings',
    select: 'price title images',
  });

  if (!purchases)
    return res.status(200).json({
      status: 'success',
      message: 'No purchases found.',
    });

  return res.status(200).json({
    status: 'success',
    data: { userId, purchases },
  });
});

exports.getUser = factory.getOne(User);
exports.getAllUsers = factory.getAll(User);
exports.updateUser = factory.updateOne(User); // not for updating password.
exports.deleteUser = factory.deleteOne(User); // admin only or the user himself
