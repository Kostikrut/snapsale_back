const { promisify } = require('util');
const jwt = require('jsonwebtoken');
const User = require('./../models/userModel');
const catchAsync = require('./../utils/catchAsync');
const AppError = require('./../utils/appError');
const sendEmail = require('./../utils/email');
const crypto = require('crypto');

const signToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN,
  });
};

const createSendToken = (user, statusCode, res) => {
  const token = signToken(user._id);
  const cookieOptions = {
    expires: new Date(
      Date.now() + process.env.JWT_COOKIE_EXPIRES_IN * 24 * 60 * 60 * 1000
    ),
    // secure: true, // for secure https
    httpOnly: true,
  };

  if (process.env.NODE_ENV === 'production') cookieOptions.secure = true;
  res.cookie('jwt', token, cookieOptions);

  // Remove password from the output
  user.password = undefined;

  res.status(statusCode).json({
    status: 'success',
    token,
    data: {
      user,
    },
  });
};

exports.createSendToken;

exports.signup = catchAsync(async (req, res, next) => {
  const newUser = await User.create({
    fullName: req.body.fullName,
    email: req.body.email,
    phone: req.body.phone,
    password: req.body.password,
    passwordConfirm: req.body.passwordConfirm,
  });

  createSendToken(newUser, 201, res);
});

//                             {{{{DO LATER}}}}      ACTIVATE USER AGAIN IF HE IS DELETED HIS ACCOUNT
exports.login = catchAsync(async (req, res, next) => {
  const { email, password } = req.body;

  // 1) Check if email and password actualy exist
  if (!email || !password)
    return next(new AppError('Please provide an email and password', 400));

  // 2) Check if user exists and the password is correct
  const user = await User.findOne({ email }).select('+password');

  if (!user || !(await user.correctPassword(password, user.password)))
    return next(new AppError('Incorrect email or password ', 401));

  // 3) Send the token to the client

  createSendToken(user, 200, res);
});

exports.protect = catchAsync(async function (req, res, next) {
  let token;

  // 1) Get the jwt and check if it exist
  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith('Bearer')
  ) {
    token = req.headers.authorization.split(' ')[1];
  }

  if (!token)
    return next(
      new AppError('You are not logged in, please log in to get access.', 401)
    );

  // 2) Verify token
  const decoded = await promisify(jwt.verify)(token, process.env.JWT_SECRET);

  // 3) Check if user that matches the token exists
  const freshUser = await User.findById(decoded.id);
  if (!freshUser)
    return next(
      new AppError(
        'The user belonging to this token does no longer exist, pleasse log in again.',
        401
      )
    );

  // 4) Check if user changed the password after the token was isssued
  if (freshUser.changedPasswordAfter(decoded.iat))
    return next(
      new AppError('User changed password recently, please log in again.', 401)
    );

  req.user = freshUser;
  next();
});

// Restrict certain user roles from access to certain route
exports.restrictTo = (...roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role))
      return next(
        new AppError('User do not have a premission to access this route.', 403)
      );

    return next();
  };
};

exports.forgotPassword = catchAsync(async (req, res, next) => {
  // 1) Get user by posted email
  const user = await User.findOne({ email: req.body.email });
  if (!user)
    return next(new AppError('There is no user with that email address.', 404));

  // 2) Create a random reset token
  const resetToken = user.createPasswordResetToken();
  await user.save({ validateBeforeSave: false });

  // 3) Send reset token to users email
  const resetUrl = `${req.protocol}://${req.get(
    'host'
  )}/api/v1/users/resetPassword/${resetToken}`;

  const message = `Forgot ypur password? Submit a PATCH request with your new password and passwordConfirm to: ${resetUrl}. \nif you did not forget your password, please ignore this email.`;

  try {
    await sendEmail({
      email: user.email,
      subject: 'Your password reset token (valid for 10 minutes)',
      message,
    });

    return res.status(200).json({
      status: 'success',
      message: 'Reset token sent to email',
    });
    next();
  } catch (err) {
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    await user.save({ validateBeforeSave: false });

    return next(
      new AppError(
        'There was a problem sending the email, please try again later.',
        500
      )
    );
  }
});

exports.resetPassword = catchAsync(async (req, res, next) => {
  // 1) Get user based on token
  const hashedToken = crypto
    .createHash('sha256')
    .update(req.params.token)
    .digest('hex');

  const user = await User.findOne({
    passwordResetToken: hashedToken,
    passwordResetExpires: { $gt: Date.now() },
  });

  // 2) Set new password if token has not expired and user exists
  if (!user) return next(new AppError('Token is invalid or has expired.', 400));

  user.password = req.body.password;
  user.passwordConfirm = req.body.passwordConfirm;
  user.passwordResetToken = undefined;
  user.passwordResetExpires = undefined;

  await user.save();
  // 3) Update changedPasswordAt property for the user

  // 4) Log the user in, send jwt
  createSendToken(user, 200, res);
});

exports.updatePassword = async (req, res, next) => {
  // 1) Get the user
  const user = await User.findById(req.user.id).select('+password');

  // 2) Check if posted password is correct
  const { currentPassword, password, passwordConfirm } = req.body;

  if (!(await user.correctPassword(currentPassword, user.password)))
    return next(
      new AppError('Your current password is wrong, Please try again.', 401)
    );

  // 3) Update the password
  user.password = password;
  user.passwordConfirm = passwordConfirm;
  await user.save();

  // 4) Log the user in
  createSendToken(user, 200, res);
};
