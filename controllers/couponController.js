const catchAsync = require('../utils/catchAsync');
const AppError = require('../utils/appError');
const Coupon = require('../models/couponModel');

exports.createCoupon = catchAsync(async (req, res, next) => {
  const {
    code,
    discountType,
    discountValue,
    expirationDate,
    usageLimit,
    minOrderValue,
    applicableCategories,
    applicableProducts,
    isActive,
  } = req.body;

  const createdBy = req.user._id;

  const coupon = await Coupon.create({
    code,
    discountType,
    discountValue,
    expirationDate,
    usageLimit,
    minOrderValue,
    applicableCategories,
    applicableProducts,
    isActive,
    createdBy,
  });

  if (!coupon)
    return next(
      new AppError('Couldnt create a coupon, please try again later.', 500)
    );

  res.status(201).json({
    status: 'success',
    data: { coupon },
  });
});

exports.getAllCoupons = catchAsync(async (req, res, next) => {
  const coupons = await Coupon.find();

  res.status(200).json({
    status: 'success',
    results: coupons.length,
    data: { coupons },
  });
});

exports.getCoupon = catchAsync(async (req, res, next) => {
  const coupon = await Coupon.findOne({ code: req.params.couponName });

  if (!coupon)
    return next(new AppError('No coupon found with that name.', 404));

  res.status(200).json({
    status: 'success',
    data: { coupon },
  });
});
