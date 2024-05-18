const catchAsync = require('./../utils/catchAsync');
const AppError = require('../utils/appError');
const factory = require('./handleFactory');
const Invoice = require('./../models/invoiceModel');

exports.getInvoiceUserId = (req, res, next) => {
  req.body.user = req.user.id;

  next();
};

exports.createInvoice = catchAsync(async (req, res, next) => {
  const invoice = await Invoice.create(req.body);

  if (!invoice)
    return next(
      new AppError('Couldnt create an invoice, please try again later.', 500)
    );

  res.status(201).json({
    status: 'success',
    data: { invoice },
  });
});

exports.getInvoice = factory.getOne(Invoice);
exports.deleteInvoice = factory.deleteOne(Invoice);
