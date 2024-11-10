const mongoose = require('mongoose');
const validator = require('validator');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

const userSchema = new mongoose.Schema({
  fullName: {
    type: String,
    required: [true, 'Please provide your full name'],
    validate: {
      validator: function (v) {
        return /^[a-zA-Z\s]+$/.test(v); // Ensure no numbers in full name
      },
      message: 'Full name should not contain numbers.',
    },
  },
  email: {
    type: String,
    unique: true,
    required: [true, 'Please provide your email address'],
    trim: true,
    lowerCase: true,
    validate: [validator.isEmail, 'Please provide a valid email address'],
  },
  phone: {
    type: Number,
    unique: true,
    required: [true, 'Please tell us your phone number'],
  },
  address: {
    city: {
      type: String,
      required: [true, 'Please provide a city'],
    },
    address: {
      type: String,
      required: [true, 'Please provide an address'],
    },
    apartment: {
      type: String,
      required: [true, 'Please provide an apartment number'],
    },
    zipCode: {
      type: String,
      required: [true, 'Please provide a zip code'],
    },
  },
  role: {
    type: String,
    enum: ['admin', 'moderator', 'user', 'maintainer'],
    default: 'user',
  },
  image: {
    filename: String,
    url: String,
  },
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
  },
});

// Hash password before saving new user data to the database
userSchema.pre('save', async function (next) {
  // only run this funtion if the password has beenn modified
  if (!this.isModified('password')) return next();

  this.password = await bcrypt.hash(this.password, 12);
  this.passwordConfirm = undefined;

  next();
});

// Filter none-active/deleted users
userSchema.pre(/^find/, function (next) {
  this.find({ isActive: { $ne: false } });

  next();
});

userSchema.pre('save', function (next) {
  // If doc is new or the password has been modified
  if (!this.isModified('password') || this.isNew) return next();

  // create time stamp of when the user changed password
  this.passwordChangedAt = Date.now() - 1000; // sometimes token created a bit before the passwordChangedAt actually being created, so i subtract 1 sec.

  next();
});

// Compare input password with user password in DB
userSchema.methods.correctPassword = async function (
  candidatePassword,
  userPassword
) {
  return await bcrypt.compare(candidatePassword, userPassword);
};

// Check if user changed his password after the jwt was isssued
userSchema.methods.changedPasswordAfter = function (JWTTimestamp) {
  if (this.passwordChangedAt) {
    const formatedTimeStamp = parseInt(
      this.passwordChangedAt.getTime() / 1000,
      10
    );
    return JWTTimestamp < formatedTimeStamp;
  }
  return false;
};

userSchema.methods.createPasswordResetToken = function () {
  const resetToken = crypto.randomBytes(32).toString('hex');

  this.passwordResetToken = crypto
    .createHash('sha256')
    .update(resetToken)
    .digest('hex');

  this.passwordResetExpires = Date.now() + 10 * 60 * 1000;

  return resetToken;
};

const User = mongoose.model('User', userSchema);

module.exports = User;
