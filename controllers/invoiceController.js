const catchAsync = require('./../utils/catchAsync');
const AppError = require('../utils/appError');
const factory = require('./handleFactory');
const Invoice = require('./../models/invoiceModel');
const mongoose = require('mongoose');
const { ObjectId } = mongoose.Types;

exports.getInvoiceUserId = (req, res, next) => {
  req.body.user = req.user._id;

  next();
};

exports.createInvoice = catchAsync(async (req, res, next) => {
  const { user, cart } = req.body;

  const invoice = await Invoice.create({ user, listings: cart });

  if (!invoice)
    return next(
      new AppError('Couldnt create an invoice, please try again later.', 500)
    );

  res.status(201).json({
    status: 'success',
    data: { invoice },
  });
});

exports.updateAddressAndShipping = catchAsync(async (req, res, next) => {
  const { user, shippingDetails } = req.body;
  const { id: invoiceId } = req.params;
  console.log(user);
  if (
    (shippingDetails.shippingType &&
      shippingDetails.address.address &&
      shippingDetails.address.city &&
      shippingDetails.address.apartment &&
      shippingDetails.address.zipCode) ||
    shippingDetails.shippingType === 'store'
  )
    shippingDetails.address = `${shippingDetails.address.city}, ${shippingDetails.address.address}, ${shippingDetails.address.apartment}, ${shippingDetails.address.zipCode}`;

  const invoice = await Invoice.findByIdAndUpdate(
    invoiceId,
    {
      shippingOpt: shippingDetails,
    },
    { new: true, runValidators: true }
  );

  if (!invoice)
    return next(
      new AppError(
        'Couldnt update address or shipping method, please fill all required fields and try again..',
        500
      )
    );

  res.status(201).json({
    status: 'success',
    data: { invoice },
  });
});

exports.getPurchaseHistory = catchAsync(async (req, res, next) => {
  const userId = new ObjectId(req.user.id);

  const invoices = await Invoice.aggregate([
    {
      $match: { user: userId, status: 'complete' },
    },
    {
      $lookup: {
        from: 'listings',
        localField: 'listings',
        foreignField: '_id',
        as: 'listingsDetails',
      },
    },
  ]);

  res.status(200).json({
    status: 'success',
    data: invoices,
  });
});

exports.getInvoice = factory.getOne(Invoice);
exports.deleteInvoice = factory.deleteOne(Invoice);
