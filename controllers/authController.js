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
  const expiresIn =
    Date.now() + process.env.JWT_COOKIE_EXPIRES_IN * 24 * 60 * 60 * 1000;

  const cookieOptions = {
    expires: new Date(expiresIn),
    // secure: true, // for secure https
    httpOnly: true,
  };

  if (process.env.NODE_ENV === 'production') cookieOptions.secure = true;
  res.cookie('jwt', token, cookieOptions);

  user.password = undefined;

  res.status(statusCode).json({
    status: 'success',
    token,
    data: {
      user,
    },
    expiresIn,
  });
};

exports.signup = catchAsync(async (req, res, next) => {
  const { fullName, email, phone, password, passwordConfirm, address } =
    req.body;

  const newUser = await User.create({
    fullName,
    email,
    phone,
    address,
    password,
    passwordConfirm,
  });

  createSendToken(newUser, 201, res);
});

//                             {{{{DO LATER}}}}      ACTIVATE USER AGAIN IF HE IS DELETED HIS ACCOUNT
exports.login = catchAsync(async (req, res, next) => {
  const { email, password } = req.body;

  if (!email || !password)
    return next(new AppError('Please provide an email and password', 400));

  const user = await User.findOne({ email }).select('+password');

  if (!user || !(await user.correctPassword(password, user.password)))
    return next(new AppError('Incorrect email or password ', 401));

  createSendToken(user, 200, res);
});

exports.protect = catchAsync(async function (req, res, next) {
  let token;

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

  const decoded = await promisify(jwt.verify)(token, process.env.JWT_SECRET);

  const freshUser = await User.findById(decoded.id);
  if (!freshUser)
    return next(
      new AppError(
        'The user belonging to this token does no longer exist, pleasse log in again.',
        401
      )
    );

  if (freshUser.changedPasswordAfter(decoded.iat))
    return next(
      new AppError('User changed password recently, please log in again.', 401)
    );

  req.user = freshUser;
  next();
});

exports.verifyStoredToken = catchAsync(async (req, res, next) => {
  if (req.user) return createSendToken(req.user, 200, res);

  return next(new AppError('No user found with this token.', 404));
});

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
  const user = await User.findOne({ email: req.body.email });
  if (!user)
    return next(new AppError('There is no user with that email address.', 404));

  const resetToken = user.createPasswordResetToken();
  await user.save({ validateBeforeSave: false });

  // const resetUrl = `${req.protocol}://${req.get(
  //   'host'
  // )}/api/v1/users/resetPassword/${resetToken}`;
  const resetUrl = `${req.protocol}://${process.env.APP_URL}/resetPassword/${resetToken}`;

  const message = `Forgot ypur password? Submit a PATCH request with your new password and passwordConfirm to: ${resetUrl}. \nif you did not forget your password, please ignore this email.`;

  try {
    await sendEmail({
      email: user.email,
      subject: 'Your password reset token (valid for 10 minutes)',
      message,
    });

    return res.status(200).json({
      status: 'success',
      message: `Reset token sent to the provided email (${user.email}). Your password reset token (valid for 10 minutes). `,
    });
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
  console.log(req.body);
  if (!req.body.password || !req.body.passwordConfirm)
    return next(
      new AppError('Please provide a password and passwordConfirm.', 400)
    );
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
