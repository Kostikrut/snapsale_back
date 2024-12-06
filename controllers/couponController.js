const catchAsync = require('../utils/catchAsync');
const AppError = require('../utils/appError');
const Coupon = require('../models/couponModel');
const Invoice = require('../models/invoiceModel');

exports.getAllCoupons = catchAsync(async (req, res, next) => {
  const coupons = await Coupon.find();

  if (!coupons)
    return next(new AppError('No coupons found, please try again later.', 404));

  res.status(200).json({
    status: 'success',
    results: coupons.length,
    data: { coupons },
  });
});

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
  const coupon = await Coupon.findOne({ code: req.params.code });

  if (!coupon)
    return next(new AppError('No coupon found with that name.', 404));

  res.status(200).json({
    status: 'success',
    data: { coupon },
  });
});

exports.applyCoupon = catchAsync(async (req, res, next) => {
  const { invoiceId, couponCode } = req.body;

  console.log(invoiceId, couponCode);
  const invoice = await Invoice.findById(invoiceId);
  if (!invoice) return next(new AppError('Invoice not found.', 404));

  const coupon = await Coupon.findOne({ code: couponCode });
  if (!coupon) return next(new AppError('Invalid coupon code.', 404));

  invoice.coupon = coupon._id;

  await invoice.save();

  res.status(200).json({
    status: 'success',
    message: 'Coupon applied successfully.',
    data: invoice,
  });
});

exports.validateCoupon = catchAsync(async (req, res, next) => {
  const { code, invoiceId } = req.body;

  const coupon = await Coupon.findOne({ code });
  if (!coupon) return next(new AppError('Invalid coupon code.', 404));

  const invoice = await Invoice.findById(invoiceId).populate('listings');
  if (!invoice)
    return next(new AppError('No invoice found with that id.', 404));

  const validation = await coupon.isValid(invoice);
  if (!validation.valid) return next(new AppError(validation.reason, 400));

  res.status(200).json({
    status: 'success',
    valid: true,
    discountType: coupon.discountType,
    discountValue: coupon.discountValue,
  });
});
