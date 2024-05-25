var $59Bnz$mongoose = require('mongoose');
var $59Bnz$dotenv = require('dotenv');
var $59Bnz$path = require('path');
var $59Bnz$express = require('express');
var $59Bnz$morgan = require('morgan');
var $59Bnz$expressratelimit = require('express-rate-limit');
var $59Bnz$helmet = require('helmet');
var $59Bnz$expressmongosanitize = require('express-mongo-sanitize');
var $59Bnz$xssclean = require('xss-clean');
var $59Bnz$hpp = require('hpp');
var $59Bnz$cors = require('cors');
var $59Bnz$compression = require('compression');
var $59Bnz$util = require('util');
var $59Bnz$jsonwebtoken = require('jsonwebtoken');
var $59Bnz$crypto = require('crypto');
var $59Bnz$validator = require('validator');
var $59Bnz$bcryptjs = require('bcryptjs');
var $59Bnz$nodemailer = require('nodemailer');
var $59Bnz$multer = require('multer');
var $59Bnz$slugify = require('slugify');

$59Bnz$dotenv.config({
  path: './config.env',
});
// Catch uncaught exceptions if not handled
process.on('uncaughtException', (err) => {
  console.log('UNCAUGHT EXCEPTION! \uD83D\uDCA5 Shutting down...');
  console.log(err.name, err.message, err);
  process.exit(1);
});
var $8127645e545f2c4c$exports = {};

var $8127645e545f2c4c$var$$parcel$__dirname = $59Bnz$path.resolve(
  __dirname,
  '..'
);

var $54fee87b29dc4d31$exports = {};
class $54fee87b29dc4d31$var$AppError extends Error {
  constructor(message, statusCode) {
    super(message);
    this.statusCode = statusCode;
    this.status = `${statusCode}`.startsWith('4') ? 'fail' : 'error';
    this.isOperational = true;
    Error.captureStackTrace(this, this.constructor);
  }
}
$54fee87b29dc4d31$exports = $54fee87b29dc4d31$var$AppError;

var $73be7ca12aa0d59c$exports = {};

const $73be7ca12aa0d59c$var$handleCastErrorDB = (err) => {
  const message = `Invalid ${err.path}: ${err.value}`;
  return new $54fee87b29dc4d31$exports(message, 400);
};
const $73be7ca12aa0d59c$var$handleValidationErrorDB = (err) => {
  const errors = Object.values(err.errors).map((el) => el.message);
  const message = `Invalid input data. ${errors.join('. ')}`;
  return new $54fee87b29dc4d31$exports(message, 400);
};
const $73be7ca12aa0d59c$var$handleJWTError = (err) =>
  new $54fee87b29dc4d31$exports('Invalid token, please log in again.', 401);
const $73be7ca12aa0d59c$var$handleExpiredJWTError = (err) =>
  new $54fee87b29dc4d31$exports(
    'Access token has expired, please log in again to get access.',
    401
  );
const $73be7ca12aa0d59c$var$sendErrorDev = (err, res) => {
  return res.status(err.statusCode).json({
    status: err.status,
    err: err,
    message: err.message,
    stack: err.stack,
  });
};
const $73be7ca12aa0d59c$var$sendErrorProd = (err, res) => {
  if (err.isOperational)
    return res.status(err.statusCode).json({
      status: err.status,
      message: err.message,
    });
  // for unknown errors in production - general error/not operational
  return res.status(500).json({
    status: 'error',
    message: 'Something went wrong',
  });
};
$73be7ca12aa0d59c$exports = (err, req, res, next) => {
  err.statusCode = err.statusCode || 500;
  err.status = err.status || 'error';
  if (process.env.NODE_ENV === 'development')
    $73be7ca12aa0d59c$var$sendErrorDev(err, res);
  if (process.env.NODE_ENV === 'production') {
    let error = {
      ...err,
    };
    if (err.name === 'CastError')
      error = $73be7ca12aa0d59c$var$handleCastErrorDB(error); //handle invalid id query
    if (err.name === 'ValidationError')
      error = $73be7ca12aa0d59c$var$handleValidationErrorDB(error); // handle validation error
    if (err.name === 'JsonWebTokenError')
      error = $73be7ca12aa0d59c$var$handleJWTError(error); // handle incorrect jwt
    if (err.name === 'TokenExpiredError')
      error = $73be7ca12aa0d59c$var$handleExpiredJWTError(error); // handle expired jwt
    $73be7ca12aa0d59c$var$sendErrorProd(error, res);
  }
  next();
};

var $3f84302d74d3e214$exports = {};

var $6914ef1dd8f3f2c6$export$7200a869094fec36;
//                             {{{{DO LATER}}}}      ACTIVATE USER AGAIN IF HE IS DELETED HIS ACCOUNT
var $6914ef1dd8f3f2c6$export$596d806903d1f59e;
var $6914ef1dd8f3f2c6$export$eda7ca9e36571553;
// Restrict certain user roles from access to certain route
var $6914ef1dd8f3f2c6$export$e1bac762c84d3b0c;
var $6914ef1dd8f3f2c6$export$66791fb2cfeec3e;
var $6914ef1dd8f3f2c6$export$dc726c8e334dd814;
var $6914ef1dd8f3f2c6$export$e2853351e15b7895;

var $6914ef1dd8f3f2c6$require$promisify = $59Bnz$util.promisify;

var $a8a42744f71bb7ce$exports = {};

const $a8a42744f71bb7ce$var$userSchema = new $59Bnz$mongoose.Schema({
  fullName: {
    type: String,
    required: [true, 'Please tell us your name'],
    trim: true,
  },
  email: {
    type: String,
    unique: true,
    required: [true, 'Please provide your email address'],
    trim: true,
    lowerCase: true,
    validate: [
      $59Bnz$validator.isEmail,
      'Please provide a valid email address',
    ],
  },
  phone: {
    type: Number,
    unique: true,
    required: [true, 'Please tell us your phone number'],
  },
  role: {
    type: String,
    enum: ['admin', 'moderator', 'user', 'maintainer'],
    default: 'user',
  },
  photo: String,
  password: {
    type: String,
    required: [true, 'Please provide a password'],
    select: false,
    minLength: 8,
  },
  passwordConfirm: {
    type: String,
    required: [true, 'Please confirm your password'],
    validate: {
      validator: function (el) {
        return el === this.password;
      },
      message: 'Passwords are not the same',
    },
  },
  passwordChangedAt: Date,
  passwordResetToken: String,
  passwordResetExpires: Date,
  isActive: {
    type: Boolean,
    default: true,
    select: false,
  },
});
// Hash password before saving new user data to the database
$a8a42744f71bb7ce$var$userSchema.pre('save', async function (next) {
  // only run this funtion if the password has beenn modified
  if (!this.isModified('password')) return next();
  this.password = await $59Bnz$bcryptjs.hash(this.password, 12); // hashing the password
  this.passwordConfirm = undefined; // clearing the password confirm field before saving the doc
  next();
});
// Filter none-active/deleted users
$a8a42744f71bb7ce$var$userSchema.pre(/^find/, function (next) {
  this.find({
    isActive: {
      $ne: false,
    },
  });
  next();
});
$a8a42744f71bb7ce$var$userSchema.pre('save', function (next) {
  // If doc is new or the password has been modified
  if (!this.isModified('password') || this.isNew) return next();
  // create time stamp of when the user changed password
  this.passwordChangedAt = Date.now() - 1000; // sometimes token created a bit before the passwordChangedAt actually being created, so i subtract 1 sec.
  next();
});
// Compare input password with user password in DB
$a8a42744f71bb7ce$var$userSchema.methods.correctPassword = async function (
  candidatePassword,
  userPassword
) {
  return await $59Bnz$bcryptjs.compare(candidatePassword, userPassword);
};
// Check if user changed his password after the jwt was isssued
$a8a42744f71bb7ce$var$userSchema.methods.changedPasswordAfter = function (
  JWTTimestamp
) {
  if (this.passwordChangedAt) {
    const formatedTimeStamp = parseInt(
      this.passwordChangedAt.getTime() / 1000,
      10
    );
    return JWTTimestamp < formatedTimeStamp;
  }
  return false;
};
$a8a42744f71bb7ce$var$userSchema.methods.createPasswordResetToken =
  function () {
    const resetToken = $59Bnz$crypto.randomBytes(32).toString('hex');
    this.passwordResetToken = $59Bnz$crypto
      .createHash('sha256')
      .update(resetToken)
      .digest('hex');
    this.passwordResetExpires = Date.now() + 600000;
    return resetToken;
  };
const $a8a42744f71bb7ce$var$User = $59Bnz$mongoose.model(
  'User',
  $a8a42744f71bb7ce$var$userSchema
);
$a8a42744f71bb7ce$exports = $a8a42744f71bb7ce$var$User;

var $3e298dfc3a4a6788$exports = {};
$3e298dfc3a4a6788$exports = (fn) => {
  return (req, res, next) => {
    fn(req, res, next).catch(next);
  };
};

var $8d2659a86160c2d5$exports = {};

const $8d2659a86160c2d5$var$sendEmail = async (options) => {
  // 1) create transporter
  const transporter = $59Bnz$nodemailer.createTransport({
    host: process.env.EMAIL_HOST,
    port: process.env.EMAIL_PORT,
    auth: {
      user: process.env.EMAIL_USERNAME,
      pass: process.env.EMAIL_PASSWORD,
    },
  });
  // 2) define email options
  const emailOptions = {
    from: 'BlastBid admin <admin@blastbid.com>',
    to: options.email,
    subject: options.subject,
    text: options.message,
  };
  // 3) send email
  await transporter.sendMail(emailOptions);
};
$8d2659a86160c2d5$exports = $8d2659a86160c2d5$var$sendEmail;

const $6914ef1dd8f3f2c6$var$signToken = (id) => {
  return $59Bnz$jsonwebtoken.sign(
    {
      id: id,
    },
    process.env.JWT_SECRET,
    {
      expiresIn: process.env.JWT_EXPIRES_IN,
    }
  );
};
const $6914ef1dd8f3f2c6$var$createSendToken = (user, statusCode, res) => {
  const token = $6914ef1dd8f3f2c6$var$signToken(user._id);
  const cookieOptions = {
    expires: new Date(
      Date.now() + process.env.JWT_COOKIE_EXPIRES_IN * 86400000
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
    token: token,
    data: {
      user: user,
    },
  });
};
$6914ef1dd8f3f2c6$export$7200a869094fec36 = $3e298dfc3a4a6788$exports(
  async (req, res, next) => {
    const newUser = await $a8a42744f71bb7ce$exports.create({
      fullName: req.body.fullName,
      email: req.body.email,
      phone: req.body.phone,
      password: req.body.password,
      passwordConfirm: req.body.passwordConfirm,
    });
    $6914ef1dd8f3f2c6$var$createSendToken(newUser, 201, res);
  }
);
$6914ef1dd8f3f2c6$export$596d806903d1f59e = $3e298dfc3a4a6788$exports(
  async (req, res, next) => {
    const { email: email, password: password } = req.body;
    // 1) Check if email and password actualy exist
    if (!email || !password)
      return next(
        new $54fee87b29dc4d31$exports(
          'Please provide an email and password',
          400
        )
      );
    // 2) Check if user exists and the password is correct
    const user = await $a8a42744f71bb7ce$exports
      .findOne({
        email: email,
      })
      .select('+password');
    if (!user || !(await user.correctPassword(password, user.password)))
      return next(
        new $54fee87b29dc4d31$exports('Incorrect email or password ', 401)
      );
    // 3) Send the token to the client
    $6914ef1dd8f3f2c6$var$createSendToken(user, 200, res);
  }
);
$6914ef1dd8f3f2c6$export$eda7ca9e36571553 = $3e298dfc3a4a6788$exports(
  async function (req, res, next) {
    let token;
    // 1) Get the jwt and check if it exist
    if (
      req.headers.authorization &&
      req.headers.authorization.startsWith('Bearer')
    )
      token = req.headers.authorization.split(' ')[1];
    if (!token)
      return next(
        new $54fee87b29dc4d31$exports(
          'You are not logged in, please log in to get access.',
          401
        )
      );
    // 2) Verify token
    const decoded = await $6914ef1dd8f3f2c6$require$promisify(
      $59Bnz$jsonwebtoken.verify
    )(token, process.env.JWT_SECRET);
    // 3) Check if user that matches the token exists
    const freshUser = await $a8a42744f71bb7ce$exports.findById(decoded.id);
    if (!freshUser)
      return next(
        new $54fee87b29dc4d31$exports(
          'The user belonging to this token does no longer exist, pleasse log in again.',
          401
        )
      );
    // 4) Check if user changed the password after the token was isssued
    if (freshUser.changedPasswordAfter(decoded.iat))
      return next(
        new $54fee87b29dc4d31$exports(
          'User changed password recently, please log in again.',
          401
        )
      );
    req.user = freshUser;
    next();
  }
);
$6914ef1dd8f3f2c6$export$e1bac762c84d3b0c = (...roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role))
      return next(
        new $54fee87b29dc4d31$exports(
          'User do not have a premission to access this route.',
          403
        )
      );
    return next();
  };
};
$6914ef1dd8f3f2c6$export$66791fb2cfeec3e = $3e298dfc3a4a6788$exports(
  async (req, res, next) => {
    // 1) Get user by posted email
    const user = await $a8a42744f71bb7ce$exports.findOne({
      email: req.body.email,
    });
    if (!user)
      return next(
        new $54fee87b29dc4d31$exports(
          'There is no user with that email address.',
          404
        )
      );
    // 2) Create a random reset token
    const resetToken = user.createPasswordResetToken();
    await user.save({
      validateBeforeSave: false,
    });
    // 3) Send reset token to users email
    const resetUrl = `${req.protocol}://${req.get(
      'host'
    )}/api/v1/users/resetPassword/${resetToken}`;
    const message = `Forgot ypur password? Submit a PATCH request with your new password and passwordConfirm to: ${resetUrl}. \nif you did not forget your password, please ignore this email.`;
    try {
      await $8d2659a86160c2d5$exports({
        email: user.email,
        subject: 'Your password reset token (valid for 10 minutes)',
        message: message,
      });
      return res.status(200).json({
        status: 'success',
        message: 'Reset token sent to email',
      });
    } catch (err) {
      user.passwordResetToken = undefined;
      user.passwordResetExpires = undefined;
      await user.save({
        validateBeforeSave: false,
      });
      return next(
        new $54fee87b29dc4d31$exports(
          'There was a problem sending the email, please try again later.',
          500
        )
      );
    }
  }
);
$6914ef1dd8f3f2c6$export$dc726c8e334dd814 = $3e298dfc3a4a6788$exports(
  async (req, res, next) => {
    // 1) Get user based on token
    const hashedToken = $59Bnz$crypto
      .createHash('sha256')
      .update(req.params.token)
      .digest('hex');
    const user = await $a8a42744f71bb7ce$exports.findOne({
      passwordResetToken: hashedToken,
      passwordResetExpires: {
        $gt: Date.now(),
      },
    });
    // 2) Set new password if token has not expired and user exists
    if (!user)
      return next(
        new $54fee87b29dc4d31$exports('Token is invalid or has expired.', 400)
      );
    user.password = req.body.password;
    user.passwordConfirm = req.body.passwordConfirm;
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    await user.save();
    // 3) Update changedPasswordAt property for the user
    // 4) Log the user in, send jwt
    $6914ef1dd8f3f2c6$var$createSendToken(user, 200, res);
  }
);
$6914ef1dd8f3f2c6$export$e2853351e15b7895 = async (req, res, next) => {
  // 1) Get the user
  const user = await $a8a42744f71bb7ce$exports
    .findById(req.user.id)
    .select('+password');
  // 2) Check if posted password is correct
  const {
    currentPassword: currentPassword,
    password: password,
    passwordConfirm: passwordConfirm,
  } = req.body;
  if (!(await user.correctPassword(currentPassword, user.password)))
    return next(
      new $54fee87b29dc4d31$exports(
        'Your current password is wrong, Please try again.',
        401
      )
    );
  // 3) Update the password
  user.password = password;
  user.passwordConfirm = passwordConfirm;
  await user.save();
  // 4) Log the user in
  $6914ef1dd8f3f2c6$var$createSendToken(user, 200, res);
};

var $4164b0240fc39eb7$export$92d3a8ebb4a83110;
var $4164b0240fc39eb7$export$241c2dc0377fb445;
var $4164b0240fc39eb7$export$ab7376b1f7e52892;
var $4164b0240fc39eb7$export$245ece31950dd4b5;
// exports.createListing = factory.createOne(Listing);
var $4164b0240fc39eb7$export$404106671cab736f;
var $4164b0240fc39eb7$export$62724aaef6132503;

var $2929609e3de36424$exports = {};

const $2929609e3de36424$var$listingSchema = new $59Bnz$mongoose.Schema(
  {
    title: {
      type: String,
      trim: true,
      required: [true, 'A listing must have a title'],
    },
    slug: {
      type: String,
    },
    category: {
      type: String,
      required: [true, 'Listing must have a category'],
    },
    tags: [String],
    description: {
      type: String,
      trim: true,
    },
    price: {
      type: Number,
      required: [true, 'product must have a price'],
      min: 0,
    },
    image: {
      filename: String,
      url: String,
      contentType: String,
    },
    createdAt: {
      type: Date,
      default: Date.now(),
    },
    ratingsAvg: {
      type: Number,
      default: 3,
      min: [1, 'Rating must be above 1'],
      max: [10, 'Rating must be blow 10'],
      set: (val) => Math.round(val * 10) / 10,
    },
    numRatings: {
      type: Number,
      default: 0,
    },
  },
  {
    toJSON: {
      virtuals: true,
    },
    toObject: {
      virtuals: true,
    },
  }
);
// index the most queried fields
$2929609e3de36424$var$listingSchema.index({
  price: 1,
  slug: 1,
});
// Make a slug for the listing
$2929609e3de36424$var$listingSchema.pre('save', function (next) {
  this.slug = $59Bnz$slugify(this.title, {
    lower: true,
  });
  next();
});
// populate reviews for the current listing
$2929609e3de36424$var$listingSchema.virtual('reviews', {
  ref: 'Review',
  foreignField: 'listing',
  localField: '_id',
});
const $2929609e3de36424$var$Listing = $59Bnz$mongoose.model(
  'Listing',
  $2929609e3de36424$var$listingSchema
);
$2929609e3de36424$exports = $2929609e3de36424$var$Listing;

var $21c466ccfc55e1a3$export$2774c37398bee8b2;
var $21c466ccfc55e1a3$export$36a479340da3c347;
var $21c466ccfc55e1a3$export$2eb5ba9a66e42816;
var $21c466ccfc55e1a3$export$3220ead45e537228;
var $21c466ccfc55e1a3$export$5d49599920443c31;

var $582891cac145949d$exports = {};
class $582891cac145949d$var$APIFeatures {
  constructor(query, queryStr) {
    this.query = query;
    this.queryStr = queryStr;
  }
  filter() {
    const queryObj = {
      ...this.queryStr,
    };
    const excludedFields = ['page', 'sort', 'fields', 'limit'];
    excludedFields.forEach((el) => delete queryObj[el]);
    // 1b/ advanced filtering
    let queryStr = JSON.stringify(queryObj);
    queryStr = queryStr.replace(/\b(gte|gt|lte|lt)\b/g, (match) => `$${match}`);
    this.query = this.query.find(JSON.parse(queryStr));
    return this;
  }
  sort() {
    if (this.queryStr.sort) {
      const sortBy = this.queryStr.sort.split(',').join(' ');
      this.query = this.query.sort(sortBy);
    } else this.query = this.query.sort('createdAt');
    return this;
  }
  limit() {
    if (this.queryStr.fields) {
      const fields = this.queryStr.fields.split(',').join(' ');
      console.log(fields);
      this.query = this.query.select(fields);
    } else this.query = this.query.select('-__v');
    return this;
  }
  paginate() {
    const page = this.queryStr.page * 1 || 1;
    const limit = this.queryStr.limit * 1;
    const skip = (page - 1) * limit;
    this.query = this.query.skip(skip).limit(limit);
    return this;
  }
}
$582891cac145949d$exports = $582891cac145949d$var$APIFeatures;

var $21c466ccfc55e1a3$require$query = $59Bnz$express.query;
$21c466ccfc55e1a3$export$2774c37398bee8b2 = (Model) =>
  $3e298dfc3a4a6788$exports(async (req, res, next) => {
    const doc = await Model.find().select('-__v');
    return res.status(200).json({
      status: 'success',
      results: doc.length,
      data: {
        data: doc,
      },
    });
  });
$21c466ccfc55e1a3$export$36a479340da3c347 = (Model) =>
  $3e298dfc3a4a6788$exports(async (req, res, next) => {
    const doc = await Model.findByIdAndDelete(req.params.id);
    if (!doc)
      return next(
        new $54fee87b29dc4d31$exports('No document found with that Id', 404)
      );
    res.status(204).json({
      status: null,
    });
  });
$21c466ccfc55e1a3$export$2eb5ba9a66e42816 = (Model, populateOpt) =>
  $3e298dfc3a4a6788$exports(async (req, res, next) => {
    let query = Model.findById(req.params.id);
    if (populateOpt) query = query.populate(populateOpt);
    const doc = await query;
    if (!doc)
      return next(
        new $54fee87b29dc4d31$exports('No document found with that Id', 404)
      );
    res.status(200).json({
      status: 'success',
      data: {
        data: doc,
      },
    });
  });
$21c466ccfc55e1a3$export$2774c37398bee8b2 = (Model) =>
  $3e298dfc3a4a6788$exports(async (req, res, next) => {
    // Allow nested GET reviews on listing
    let filter = {};
    if (req.params.listingId)
      filter = {
        listing: req.params.listingId,
      };
    // BUID QUERY
    const features = new $582891cac145949d$exports(
      Model.find(filter),
      req.query
    )
      .filter()
      .sort()
      .limit()
      .paginate();
    // EXECUTE QUERY
    const docs = await features.query;
    // RESPONSE
    res.status(200).json({
      status: 'success',
      results: docs.length,
      data: {
        docs: docs,
      },
    });
  });
$21c466ccfc55e1a3$export$3220ead45e537228 = (Model) =>
  $3e298dfc3a4a6788$exports(async (req, res, next) => {
    const doc = await Model.findByIdAndUpdate(req.params.id, req.body, {
      new: true,
      runValidators: true,
    });
    if (!doc)
      return next(
        new $54fee87b29dc4d31$exports('No document found with that Id', 404)
      );
    res.status(200).json({
      status: 'success',
      data: {
        data: doc,
      },
    });
  });
$21c466ccfc55e1a3$export$5d49599920443c31 = (Model) =>
  $3e298dfc3a4a6788$exports(async (req, res, next) => {
    const doc = await Model.create(req.body);
    res.status(201).json({
      status: 'success',
      data: {
        doc: doc,
      },
    });
  });

// Set up multer storage
const $4164b0240fc39eb7$var$storage = $59Bnz$multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + $59Bnz$path.extname(file.originalname));
  },
});
// Multer filter to ensure only image files are uploaded
const $4164b0240fc39eb7$var$fileFilter = (req, file, cb) => {
  if (file.mimetype.startsWith('image')) cb(null, true);
  else
    cb(
      new $54fee87b29dc4d31$exports(
        'Not an image! Please upload only images.',
        400
      ),
      false
    );
};
const $4164b0240fc39eb7$var$upload = $59Bnz$multer({
  storage: $4164b0240fc39eb7$var$storage,
  fileFilter: $4164b0240fc39eb7$var$fileFilter,
});
$4164b0240fc39eb7$export$92d3a8ebb4a83110 =
  $4164b0240fc39eb7$var$upload.single('image');
$4164b0240fc39eb7$export$241c2dc0377fb445 = $3e298dfc3a4a6788$exports(
  async (req, res) => {
    const {
      title: title,
      description: description,
      category: category,
      tags: tags,
      price: price,
    } = req.body;
    let image = null;
    if (req.file)
      image = {
        filename: req.file.filename,
        url: `/uploads/${req.file.filename}`,
      };
    const listing = await $2929609e3de36424$exports.create({
      title: title,
      tags: tags,
      category: category,
      description: description,
      price: price,
      image: image,
    });
    res.status(201).json({
      status: 'success',
      data: {
        listing: listing,
      },
    });
  }
);
$4164b0240fc39eb7$export$ab7376b1f7e52892 = $3e298dfc3a4a6788$exports(
  async (req, res, next) => {
    const listing = await $2929609e3de36424$exports
      .findById(req.params.id)
      .populate('reviews');
    if (!listing)
      return next(
        new $54fee87b29dc4d31$exports('No listing found with that id.')
      );
    res.status(200).json({
      status: 'success',
      data: {
        listing: listing,
      },
    });
  }
);
$4164b0240fc39eb7$export$245ece31950dd4b5 =
  $21c466ccfc55e1a3$export$2774c37398bee8b2($2929609e3de36424$exports);
$4164b0240fc39eb7$export$ab7376b1f7e52892 =
  $21c466ccfc55e1a3$export$2eb5ba9a66e42816($2929609e3de36424$exports, {
    path: 'reviews',
  });
$4164b0240fc39eb7$export$404106671cab736f =
  $21c466ccfc55e1a3$export$3220ead45e537228($2929609e3de36424$exports);
$4164b0240fc39eb7$export$62724aaef6132503 =
  $21c466ccfc55e1a3$export$36a479340da3c347($2929609e3de36424$exports);

var $10322a55c3f11671$exports = {};

var $92aaa72f8994755d$export$67cfcabed6353920;
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
var $92aaa72f8994755d$export$e42a3d813dd6123f;
var $92aaa72f8994755d$export$98596c466f7b9045;
var $92aaa72f8994755d$export$c3d3086f9027c35a;
var $92aaa72f8994755d$export$7019c694ef9e681d;
var $92aaa72f8994755d$export$189a68d831f3e4ec;
var $22c80c5bab1b472a$exports = {};

const $22c80c5bab1b472a$var$reviewSchema = new $59Bnz$mongoose.Schema(
  {
    title: {
      type: String,
      required: [true, 'Areview must have a title.'],
      trim: true,
      maxLength: 100,
    },
    content: {
      type: String,
      required: [true, 'A review must have a review content.'],
    },
    rating: {
      type: Number,
      required: [true, 'A review must have rating.'],
      min: 1,
      max: 10,
      default: 0,
    },
    createdAt: {
      type: String,
      default: Date.now,
    },
    listing: {
      type: $59Bnz$mongoose.Schema.ObjectId,
      ref: 'Listing',
      required: [true, 'Review must belog to listing'],
    },
    user: {
      type: $59Bnz$mongoose.Schema.ObjectId,
      ref: 'User',
      required: [true, 'Review must belong to user.'],
    },
  },
  {
    toJSON: {
      virtuals: true,
    },
    toObject: {
      virtuals: true,
    },
  }
);
// restrict only ovly one review to a listing
$22c80c5bab1b472a$var$reviewSchema.index(
  {
    listing: 1,
    user: 1,
  },
  {
    unique: true,
  }
);
$22c80c5bab1b472a$var$reviewSchema.pre(/^find/, function (next) {
  this.populate({
    path: 'user',
    select: 'fullName photo',
  });
  next();
});
// Calculate averages functionality
$22c80c5bab1b472a$var$reviewSchema.statics.calcAvgRatings = async function (
  listingId
) {
  const stats = await this.aggregate([
    {
      $match: {
        listing: listingId,
      },
    },
    {
      $group: {
        _id: '$listing',
        numRatings: {
          $sum: 1,
        },
        avgRating: {
          $avg: '$rating',
        },
      },
    },
  ]);
  if (stats.length > 0)
    await $2929609e3de36424$exports.findByIdAndUpdate(listingId, {
      ratingsAvg: stats[0].avgRating,
      numRatings: stats[0].numRatings,
    });
  else
    await $2929609e3de36424$exports.findByIdAndUpdate(listingId, {
      ratingsAvg: 0,
      numRatings: 0,
    });
};
// Persist the rating stats after creating the review
$22c80c5bab1b472a$var$reviewSchema.post('save', function () {
  this.constructor.calcAvgRatings(this.listing);
});
// Calculate the ratings after editing or deleting a review
$22c80c5bab1b472a$var$reviewSchema.post(/^findOneAnd/, async function (doc) {
  await doc.constructor.calcAvgRatings(doc.listing);
});
const $22c80c5bab1b472a$var$Review = $59Bnz$mongoose.model(
  'Review',
  $22c80c5bab1b472a$var$reviewSchema
);
$22c80c5bab1b472a$exports = $22c80c5bab1b472a$var$Review;

var $413e4fce95d45b5d$exports = {};

const $413e4fce95d45b5d$var$invoiceSchema = new $59Bnz$mongoose.Schema(
  {
    user: {
      type: $59Bnz$mongoose.Schema.ObjectId,
      ref: 'User',
      required: [true, 'Invoice must belong to a user.'],
    },
    listings: {
      type: [$59Bnz$mongoose.Schema.ObjectId],
      ref: 'Listing',
      required: [true, 'Invoice must have at least one listing.'],
    },
    totalPrice: {
      type: Number,
      default: 0,
      min: [0, 'price can not be less than 0.'],
    },
    discount: {
      type: Number,
      min: [0, 'Discount can not be less than 0.'],
      max: [1, 'Discount can not be above 1.'],
      default: 0,
    },
    currency: {
      type: String,
      enum: ['USD', 'EUR', 'ILS'],
      default: 'USD',
    },
    isPaid: {
      type: Boolean,
      default: false,
    },
    status: {
      type: String,
      enum: ['pending', 'canceled', 'rejected', 'approved'],
      default: 'pending',
    },
    createdAt: {
      type: Date,
      default: Date.now,
    },
  },
  {
    toJSON: {
      virtuals: true,
    },
    toObject: {
      virtuals: true,
    },
  }
);
// Calculate total price
$413e4fce95d45b5d$var$invoiceSchema.post('save', async function (doc) {
  await doc
    .populate({
      path: 'listings',
      select: 'price title',
    })
    .execPopulate();
  const totalListingsPrice = doc.listings.reduce(
    (total, listing) => total + listing.price,
    0
  );
  doc.totalPrice = (
    totalListingsPrice -
    totalListingsPrice * doc.discount
  ).toFixed(2);
  await $413e4fce95d45b5d$var$Invoice.updateOne(
    {
      _id: doc._id,
    },
    {
      totalPrice: doc.totalPrice,
    }
  );
});
const $413e4fce95d45b5d$var$Invoice = $59Bnz$mongoose.model(
  'Invoice',
  $413e4fce95d45b5d$var$invoiceSchema
);
$413e4fce95d45b5d$exports = $413e4fce95d45b5d$var$Invoice;

$92aaa72f8994755d$export$67cfcabed6353920 = (req, res, next) => {
  //Aloow nested routes
  req.body.listing = req.params.listingId;
  req.body.user = req.user.id;
  next();
};
$92aaa72f8994755d$export$e42a3d813dd6123f =
  $21c466ccfc55e1a3$export$5d49599920443c31($22c80c5bab1b472a$exports);
$92aaa72f8994755d$export$98596c466f7b9045 =
  $21c466ccfc55e1a3$export$2774c37398bee8b2($22c80c5bab1b472a$exports);
$92aaa72f8994755d$export$c3d3086f9027c35a =
  $21c466ccfc55e1a3$export$2eb5ba9a66e42816($22c80c5bab1b472a$exports);
$92aaa72f8994755d$export$7019c694ef9e681d =
  $21c466ccfc55e1a3$export$3220ead45e537228($22c80c5bab1b472a$exports);
$92aaa72f8994755d$export$189a68d831f3e4ec =
  $21c466ccfc55e1a3$export$36a479340da3c347($22c80c5bab1b472a$exports);

const $10322a55c3f11671$var$router = $59Bnz$express.Router({
  mergeParams: true,
});
$10322a55c3f11671$var$router.use($6914ef1dd8f3f2c6$export$eda7ca9e36571553);
$10322a55c3f11671$var$router
  .route('/')
  .get($92aaa72f8994755d$export$98596c466f7b9045);
$10322a55c3f11671$var$router
  .route('/:id')
  .post(
    $6914ef1dd8f3f2c6$export$e1bac762c84d3b0c('user'),
    $92aaa72f8994755d$export$67cfcabed6353920,
    $92aaa72f8994755d$export$e42a3d813dd6123f
  )
  .get($92aaa72f8994755d$export$c3d3086f9027c35a)
  .patch(
    $6914ef1dd8f3f2c6$export$e1bac762c84d3b0c('user'),
    $92aaa72f8994755d$export$7019c694ef9e681d
  )
  .delete(
    $6914ef1dd8f3f2c6$export$e1bac762c84d3b0c('moderator', 'admin', 'user'),
    $92aaa72f8994755d$export$189a68d831f3e4ec
  );
$10322a55c3f11671$exports = $10322a55c3f11671$var$router;

const $3f84302d74d3e214$var$router = $59Bnz$express.Router();
$3f84302d74d3e214$var$router
  .route('/')
  .get($4164b0240fc39eb7$export$245ece31950dd4b5)
  .post(
    $6914ef1dd8f3f2c6$export$eda7ca9e36571553,
    $6914ef1dd8f3f2c6$export$e1bac762c84d3b0c('maintainer', 'admin'),
    $4164b0240fc39eb7$export$92d3a8ebb4a83110,
    $4164b0240fc39eb7$export$241c2dc0377fb445
  );
$3f84302d74d3e214$var$router
  .route('/:id')
  .get($4164b0240fc39eb7$export$ab7376b1f7e52892)
  .patch(
    $6914ef1dd8f3f2c6$export$eda7ca9e36571553,
    $6914ef1dd8f3f2c6$export$e1bac762c84d3b0c('maintainer', 'admin'),
    $4164b0240fc39eb7$export$404106671cab736f
  )
  .delete(
    $6914ef1dd8f3f2c6$export$eda7ca9e36571553,
    $6914ef1dd8f3f2c6$export$e1bac762c84d3b0c('maintainer', 'admin'),
    $4164b0240fc39eb7$export$62724aaef6132503
  );
$3f84302d74d3e214$var$router.use(
  '/:listingId/reviews',
  $10322a55c3f11671$exports
);
$3f84302d74d3e214$exports = $3f84302d74d3e214$var$router;

var $108d6475fd2da75d$exports = {};

var $ad62a74a8378735d$export$8ddaddf355aae59c;
// Deactivate user
var $ad62a74a8378735d$export$8788023029506852;
// Create users (Admin access only)
var $ad62a74a8378735d$export$3493b8991d49f558;
var $ad62a74a8378735d$export$dd7946daa6163e94;
var $ad62a74a8378735d$export$a52a3451f1550587;
var $ad62a74a8378735d$export$7cbf767827cd68ba;
var $ad62a74a8378735d$export$69093b9c569a5b5b;
var $ad62a74a8378735d$export$e3ac7a5d19605772;
var $ad62a74a8378735d$export$7d0f10f273c0438a;

const $ad62a74a8378735d$var$filterObj = function (bodyObj, allowedFieldsArr) {
  const newBodyObj = {};
  Object.keys(bodyObj).forEach((el) => {
    if (allowedFieldsArr.includes(el)) newBodyObj[el] = bodyObj[el];
  });
  return newBodyObj;
};
$ad62a74a8378735d$export$8ddaddf355aae59c = $3e298dfc3a4a6788$exports(
  async (req, res, next) => {
    // 1) Create an error if user posts password data
    if (req.body.password || req.body.passwordConfirm)
      return next(
        new $54fee87b29dc4d31$exports(
          'This route is not for password update, please use /updateMyPassword.',
          400
        )
      );
    // 2) Filter out unwanted fields
    const filteredBody = $ad62a74a8378735d$var$filterObj(req.body, [
      'fullName',
      'email',
      'phone',
      'location',
    ]);
    // 3) Update user doc
    const updatedUser = await $a8a42744f71bb7ce$exports.findByIdAndUpdate(
      req.user.id,
      filteredBody,
      {
        new: true,
        runValidators: true,
      }
    );
    res.status(200).json({
      status: 'success',
      user: updatedUser,
    });
  }
);
$ad62a74a8378735d$export$8788023029506852 = $3e298dfc3a4a6788$exports(
  async (req, res, next) => {
    const user = await $a8a42744f71bb7ce$exports.findByIdAndUpdate(
      req.user.id,
      {
        isActive: false,
      }
    );
    res.status(204).json({
      status: 'success',
    });
  }
);
$ad62a74a8378735d$export$3493b8991d49f558 = $3e298dfc3a4a6788$exports(
  async (req, res, next) => {
    const newUser = await $a8a42744f71bb7ce$exports.create(req.body);
    if (!newUser)
      next(
        new $54fee87b29dc4d31$exports(
          "Couldn't create user, please try again later.",
          500
        )
      );
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
  }
);
$ad62a74a8378735d$export$dd7946daa6163e94 = (req, res, next) => {
  req.params.id = req.user.id;
  next();
};
$ad62a74a8378735d$export$a52a3451f1550587 = $3e298dfc3a4a6788$exports(
  async (req, res) => {
    const userId = req.user._id;
    const purchases = await $413e4fce95d45b5d$exports
      .find({
        user: userId,
        status: 'approved',
      })
      ?.populate({
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
      data: {
        userId: userId,
        purchases: purchases,
      },
    });
  }
);
$ad62a74a8378735d$export$7cbf767827cd68ba =
  $21c466ccfc55e1a3$export$2eb5ba9a66e42816($a8a42744f71bb7ce$exports);
$ad62a74a8378735d$export$69093b9c569a5b5b =
  $21c466ccfc55e1a3$export$2774c37398bee8b2($a8a42744f71bb7ce$exports);
$ad62a74a8378735d$export$e3ac7a5d19605772 =
  $21c466ccfc55e1a3$export$3220ead45e537228($a8a42744f71bb7ce$exports); // not for updating password.
$ad62a74a8378735d$export$7d0f10f273c0438a =
  $21c466ccfc55e1a3$export$36a479340da3c347($a8a42744f71bb7ce$exports); // admin only or the user himself

const $108d6475fd2da75d$var$router = $59Bnz$express.Router();
$108d6475fd2da75d$var$router.post(
  '/signup',
  $6914ef1dd8f3f2c6$export$7200a869094fec36
);
$108d6475fd2da75d$var$router.post(
  '/login',
  $6914ef1dd8f3f2c6$export$596d806903d1f59e
);
$108d6475fd2da75d$var$router.post(
  '/forgotPassword',
  $6914ef1dd8f3f2c6$export$66791fb2cfeec3e
);
$108d6475fd2da75d$var$router.post(
  '/createUser',
  $6914ef1dd8f3f2c6$export$eda7ca9e36571553,
  $6914ef1dd8f3f2c6$export$e1bac762c84d3b0c('admin'),
  $ad62a74a8378735d$export$3493b8991d49f558
);
$108d6475fd2da75d$var$router.patch(
  '/resetPassword/:token',
  $6914ef1dd8f3f2c6$export$dc726c8e334dd814
);
$108d6475fd2da75d$var$router.use($6914ef1dd8f3f2c6$export$eda7ca9e36571553);
$108d6475fd2da75d$var$router.get(
  '/me',
  $ad62a74a8378735d$export$dd7946daa6163e94,
  $ad62a74a8378735d$export$7cbf767827cd68ba
);
$108d6475fd2da75d$var$router.get(
  '/purchaseHistory',
  $ad62a74a8378735d$export$a52a3451f1550587
);
$108d6475fd2da75d$var$router.patch(
  '/updateMe',
  $ad62a74a8378735d$export$8ddaddf355aae59c
);
$108d6475fd2da75d$var$router.patch(
  '/updateMyPassword',
  $6914ef1dd8f3f2c6$export$e2853351e15b7895
);
$108d6475fd2da75d$var$router.delete(
  '/deleteMe',
  $ad62a74a8378735d$export$8788023029506852
); // Deactivates the user
$108d6475fd2da75d$var$router
  .route('/')
  .get($ad62a74a8378735d$export$69093b9c569a5b5b);
$108d6475fd2da75d$var$router
  .route('/:id')
  .get($ad62a74a8378735d$export$7cbf767827cd68ba)
  .patch(
    $6914ef1dd8f3f2c6$export$e1bac762c84d3b0c('user'),
    $ad62a74a8378735d$export$e3ac7a5d19605772
  )
  .delete(
    $6914ef1dd8f3f2c6$export$e1bac762c84d3b0c('admin'),
    $ad62a74a8378735d$export$7d0f10f273c0438a
  );
$108d6475fd2da75d$exports = $108d6475fd2da75d$var$router;

var $a388c6d6ecbe70d6$exports = {};

var $8e1ac941c7c3da9c$export$360f4895d5ceb7fc;
var $8e1ac941c7c3da9c$export$4b747aa0b0d055dc;
var $8e1ac941c7c3da9c$export$7f91e787f240fc92;
var $8e1ac941c7c3da9c$export$7bf985859bf149af;

$8e1ac941c7c3da9c$export$360f4895d5ceb7fc = (req, res, next) => {
  req.body.user = req.user.id;
  next();
};
$8e1ac941c7c3da9c$export$4b747aa0b0d055dc = $3e298dfc3a4a6788$exports(
  async (req, res, next) => {
    const invoice = await $413e4fce95d45b5d$exports.create(req.body);
    if (!invoice)
      return next(
        new $54fee87b29dc4d31$exports(
          'Couldnt create an invoice, please try again later.',
          500
        )
      );
    res.status(201).json({
      status: 'success',
      data: {
        invoice: invoice,
      },
    });
  }
);
$8e1ac941c7c3da9c$export$7f91e787f240fc92 =
  $21c466ccfc55e1a3$export$2eb5ba9a66e42816($413e4fce95d45b5d$exports);
$8e1ac941c7c3da9c$export$7bf985859bf149af =
  $21c466ccfc55e1a3$export$36a479340da3c347($413e4fce95d45b5d$exports);

var $b50ef021a534dbc8$export$2de1c5c9ead290a3;
var $b50ef021a534dbc8$export$c61505d529d9f25;

$59Bnz$dotenv.config({
  path: './config.env',
});
const {
  PAYPAL_CLIENT_ID: $b50ef021a534dbc8$var$PAYPAL_CLIENT_ID,
  PAYPAL_CLIENT_SECRET: $b50ef021a534dbc8$var$PAYPAL_CLIENT_SECRET,
} = process.env;
const $b50ef021a534dbc8$var$base = 'https://api-m.sandbox.paypal.com';
const $b50ef021a534dbc8$var$generateAccessToken = async () => {
  try {
    if (
      !$b50ef021a534dbc8$var$PAYPAL_CLIENT_ID ||
      !$b50ef021a534dbc8$var$PAYPAL_CLIENT_SECRET
    )
      throw new Error('MISSING_API_CREDENTIALS');
    const auth = Buffer.from(
      $b50ef021a534dbc8$var$PAYPAL_CLIENT_ID +
        ':' +
        $b50ef021a534dbc8$var$PAYPAL_CLIENT_SECRET
    ).toString('base64');
    const response = await fetch(
      `${$b50ef021a534dbc8$var$base}/v1/oauth2/token`,
      {
        method: 'POST',
        body: 'grant_type=client_credentials',
        headers: {
          Authorization: `Basic ${auth}`,
        },
      }
    );
    const data = await response.json();
    return data.access_token;
  } catch (error) {
    console.error('Failed to generate Access Token:', error);
  }
};
const $b50ef021a534dbc8$var$createOrder = async (cart) => {
  const accessToken = await $b50ef021a534dbc8$var$generateAccessToken();
  const url = `${$b50ef021a534dbc8$var$base}/v2/checkout/orders`;
  const payload = {
    intent: 'CAPTURE',
    purchase_units: [
      {
        amount: {
          currency_code: cart.currency,
          value: cart.totalPrice,
        },
      },
    ],
  };
  const response = await fetch(url, {
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${accessToken}`,
    },
    method: 'POST',
    body: JSON.stringify(payload),
  });
  return $b50ef021a534dbc8$var$handleResponse(response);
};
const $b50ef021a534dbc8$var$captureOrder = async (orderID) => {
  const accessToken = await $b50ef021a534dbc8$var$generateAccessToken();
  const url = `${$b50ef021a534dbc8$var$base}/v2/checkout/orders/${orderID}/capture`;
  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${accessToken}`,
    },
  });
  return $b50ef021a534dbc8$var$handleResponse(response);
};
async function $b50ef021a534dbc8$var$handleResponse(response) {
  try {
    const jsonResponse = await response.json();
    return {
      jsonResponse: jsonResponse,
      httpStatusCode: response.status,
    };
  } catch (err) {
    const errorMessage = await response.text();
    throw new Error(errorMessage);
  }
}
$b50ef021a534dbc8$export$2de1c5c9ead290a3 = $3e298dfc3a4a6788$exports(
  async (req, res, next) => {
    const cart = await $413e4fce95d45b5d$exports.findById(req.params.id);
    const { jsonResponse: jsonResponse, httpStatusCode: httpStatusCode } =
      await $b50ef021a534dbc8$var$createOrder(cart);
    if (!httpStatusCode || !jsonResponse)
      return next(
        new $54fee87b29dc4d31$exports('Failed to create order.', 500)
      );
    return res.status(httpStatusCode).json(jsonResponse);
  }
);
$b50ef021a534dbc8$export$c61505d529d9f25 = $3e298dfc3a4a6788$exports(
  async (req, res, next) => {
    const { orderID: orderID, id: invoiceID } = req.params;
    const { jsonResponse: jsonResponse, httpStatusCode: httpStatusCode } =
      await $b50ef021a534dbc8$var$captureOrder(orderID);
    if (!jsonResponse || !httpStatusCode)
      return next(
        new $54fee87b29dc4d31$exports('Failed to capture order.', 500)
      );
    if (jsonResponse?.status === 'COMPLETED')
      await $413e4fce95d45b5d$exports.updateOne(
        {
          _id: invoiceID,
        },
        {
          status: 'approved',
          isPaid: true,
        }
      );
    if (jsonResponse?.name === 'UNPROCESSABLE_ENTITY')
      await $413e4fce95d45b5d$exports.updateOne(
        {
          _id: invoiceID,
        },
        {
          status: 'canceled',
          isPaid: false,
        }
      );
    return res.status(httpStatusCode).json(jsonResponse);
  }
);

const $a388c6d6ecbe70d6$var$router = $59Bnz$express.Router();
$a388c6d6ecbe70d6$var$router
  .route('/')
  .get(
    $6914ef1dd8f3f2c6$export$eda7ca9e36571553,
    $6914ef1dd8f3f2c6$export$e1bac762c84d3b0c('admin', 'user'),
    $8e1ac941c7c3da9c$export$7f91e787f240fc92
  )
  .post(
    $6914ef1dd8f3f2c6$export$eda7ca9e36571553,
    $8e1ac941c7c3da9c$export$360f4895d5ceb7fc,
    $8e1ac941c7c3da9c$export$4b747aa0b0d055dc
  );
$a388c6d6ecbe70d6$var$router
  .route('/:id')
  .delete(
    $6914ef1dd8f3f2c6$export$eda7ca9e36571553,
    $6914ef1dd8f3f2c6$export$e1bac762c84d3b0c('admin'),
    $8e1ac941c7c3da9c$export$7bf985859bf149af
  );
$a388c6d6ecbe70d6$var$router
  .route('/:id/orders')
  .post(
    $6914ef1dd8f3f2c6$export$eda7ca9e36571553,
    $b50ef021a534dbc8$export$2de1c5c9ead290a3
  );
$a388c6d6ecbe70d6$var$router
  .route('/:id/orders/:orderID/capture')
  .post(
    $6914ef1dd8f3f2c6$export$eda7ca9e36571553,
    $b50ef021a534dbc8$export$c61505d529d9f25
  );
$a388c6d6ecbe70d6$exports = $a388c6d6ecbe70d6$var$router;

const $8127645e545f2c4c$var$app = $59Bnz$express();
$8127645e545f2c4c$var$app.use(
  $59Bnz$express.static(
    $59Bnz$path.join($8127645e545f2c4c$var$$parcel$__dirname, 'public')
  )
);
$8127645e545f2c4c$var$app.use(
  '/uploads',
  $59Bnz$express.static(
    $59Bnz$path.join($8127645e545f2c4c$var$$parcel$__dirname, 'uploads')
  )
);
$8127645e545f2c4c$var$app.use($59Bnz$cors());
$8127645e545f2c4c$var$app.options('*', $59Bnz$cors());
// Set security http headers
$8127645e545f2c4c$var$app.use($59Bnz$helmet());
// Dev logging
if (process.env.NODE_ENV === 'development')
  $8127645e545f2c4c$var$app.use($59Bnz$morgan('dev'));
// Limit too many requests from the same API
const $8127645e545f2c4c$var$limiter = $59Bnz$expressratelimit({
  max: 200,
  windowMs: 3600000,
  message: 'To many requests from this IP, please try again in an hour.',
});
$8127645e545f2c4c$var$app.use('/api', $8127645e545f2c4c$var$limiter);
// Body parser - get the body from the request
$8127645e545f2c4c$var$app.use(
  $59Bnz$express.json({
    limit: '10kb',
  })
);
// Data sanitization against noSQL query injection
$8127645e545f2c4c$var$app.use($59Bnz$expressmongosanitize());
// Data sanitization against cross side scripting atacks - XSS
$8127645e545f2c4c$var$app.use($59Bnz$xssclean());
// Prevent parameter pollution - using only the last duplicate parameter
$8127645e545f2c4c$var$app.use($59Bnz$hpp());
$8127645e545f2c4c$var$app.use($59Bnz$compression());
$8127645e545f2c4c$var$app.use('/api/v1/listings', $3f84302d74d3e214$exports);
$8127645e545f2c4c$var$app.use('/api/v1/users', $108d6475fd2da75d$exports);
$8127645e545f2c4c$var$app.use('/api/v1/reviews', $10322a55c3f11671$exports);
$8127645e545f2c4c$var$app.use('/api/v1/invoices', $a388c6d6ecbe70d6$exports);
$8127645e545f2c4c$var$app.all('*', (req, res, next) => {
  next(
    new $54fee87b29dc4d31$exports(
      `Can't find ${req.originalUrl} on this server!`,
      404
    )
  );
});
$8127645e545f2c4c$var$app.use($73be7ca12aa0d59c$exports);
$8127645e545f2c4c$exports = $8127645e545f2c4c$var$app;

const $c4652f24b6b3a0a3$var$DB = process.env.DATABASE.replace(
  '<PASSWORD>',
  process.env.DATABASE_PASSWORD
);
// Make a connection to mongoDB
$59Bnz$mongoose
  .connect($c4652f24b6b3a0a3$var$DB, {
    useNewUrlParser: true,
  })
  .then((con) => console.log('Successfully connected to database'));
// Define port
const $c4652f24b6b3a0a3$var$port = process.env.PORT || 3000;
// Run server
const $c4652f24b6b3a0a3$var$server = $8127645e545f2c4c$exports.listen(
  $c4652f24b6b3a0a3$var$port,
  () => console.log(`App is listening on port ${$c4652f24b6b3a0a3$var$port}...`)
);
// Catch any unhandled promise rejection from the whole app
process.on('unhandledRejection', (err) => {
  console.log('UNHANDLED REJECTION! \uD83D\uDCA5 Shutting down...');
  console.log(err.name, err.message, err);
  // gracefull shutdown
  $c4652f24b6b3a0a3$var$server.close(() => {
    process.exit(1);
  });
});

//# sourceMappingURL=index.js.map
