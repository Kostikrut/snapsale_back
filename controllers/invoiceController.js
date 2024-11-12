const mongoose = require('mongoose');

const catchAsync = require('./../utils/catchAsync');
const AppError = require('../utils/appError');
const factory = require('./handleFactory');
const Invoice = require('./../models/invoiceModel');
const Listing = require('./../models/listingModel');
const { ObjectId } = mongoose.Types;

exports.getInvoiceUserId = (req, res, next) => {
  req.body.user = req.user._id;

  next();
};

const isListingsExist = async (listingsArr) => {
  const uniqueListingIds = [
    ...new Set(listingsArr.map((listing) => listing._id)),
  ];

  const listings = await Listing.find({ _id: { $in: uniqueListingIds } });

  return listings.length === uniqueListingIds.length;
};

exports.createInvoice = catchAsync(async (req, res, next) => {
  const { user, cart } = req.body;
  const listingsExist = await isListingsExist(cart);

  if (!listingsExist)
    return next(new AppError('One or more listings do not longer exist.', 404));

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

exports.createGuestInvoice = catchAsync(async (req, res, next) => {
  const { guestInfo, cart, shippingOpt } = req.body;

  if (
    !guestInfo ||
    !guestInfo.fullName ||
    !guestInfo.phone ||
    !guestInfo.email
  ) {
    return next(
      new AppError(
        'Please provide full name, phone, and email for guest checkout.',
        400
      )
    );
  }

  const listingsExist = await isListingsExist(cart);
  if (!listingsExist) {
    return next(new AppError('One or more listings no longer exist.', 404));
  }

  const filteredGuestInfo = {
    fullName: guestInfo.fullName,
    phone: guestInfo.phone,
    email: guestInfo.email,
  };

  const invoice = await Invoice.create({
    guestInfo: filteredGuestInfo,
    listings: cart,
    shippingOpt,
  });

  if (!invoice) {
    return next(
      new AppError('Could not create an invoice, please try again later.', 500)
    );
  }

  res.status(201).json({
    status: 'success',
    data: { invoice },
  });
});

exports.updateAddressAndShipping = catchAsync(async (req, res, next) => {
  const { shippingDetails } = req.body;
  const { id: invoiceId } = req.params;
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
