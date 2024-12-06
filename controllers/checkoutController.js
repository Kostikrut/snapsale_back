const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const catchAsync = require('../utils/catchAsync');
const Invoice = require('../models/invoiceModel');
const Listing = require('../models/listingModel');
const Coupon = require('../models/couponModel');
const AppError = require('../utils/appError');
const { sendCheckoutEmail } = require('../utils/email');

exports.createCheckoutSession = catchAsync(async (req, res, next) => {
  const invoice = await Invoice.findById(req.params.id).populate('user');

  if (!invoice) {
    return next(new AppError('Invoice not found', 404));
  }

  let couponDiscount = 0;
  let isFixedValue = false;

  // Validate and apply coupon
  if (invoice.coupon) {
    const coupon = await Coupon.findOne({ _id: invoice.coupon });

    if (!coupon) {
      return next(new AppError('Coupon not found', 404));
    }

    const couponValidation = await coupon.isValid(invoice);
    if (!couponValidation.valid) {
      return next(new AppError(couponValidation.message, 400));
    }

    if (coupon.discountType === 'percentage') {
      couponDiscount = coupon.discountValue / 100;
    } else if (coupon.discountType === 'fixed') {
      couponDiscount = coupon.discountValue;
      isFixedValue = true;
    } else {
      return next(new AppError('Unsupported coupon type', 400));
    }
  }

  // Generate line items from listings
  const items = await Promise.all(
    invoice.listings.map(async (item) => {
      const listing = await Listing.findById(item._id);

      if (!listing) {
        return next(
          new AppError(`Listing with an id of ${item._id} not found`, 404)
        );
      }

      const itemFullTitle =
        listing.title +
        ' ' +
        item.variants.map((variant) => variant.type).join(' ');

      const itemFullPrice = item.variants.reduce((acc, variant) => {
        return acc + +variant.price;
      }, +listing.price);

      const itemDiscount = itemFullPrice * (item?.discount / 100 || 0);

      let finalItemPrice = itemFullPrice - itemDiscount;

      // Apply coupon discount
      if (isFixedValue) {
        const proportionalDiscount =
          couponDiscount * (finalItemPrice / invoice.total);
        finalItemPrice -= proportionalDiscount;
      } else {
        finalItemPrice *= 1 - couponDiscount;
      }

      return {
        price_data: {
          currency: 'usd',
          product_data: {
            name: itemFullTitle,
          },
          unit_amount: Math.max(Math.round(finalItemPrice * 100), 0),
        },
        quantity: item.amount || 1,
      };
    })
  );

  // Add shipping price
  let shippingPrice = 0;
  if (invoice.shippingOpt.shippingType === 'standard') {
    shippingPrice = +process.env.STANDARD_SHIPPING_PRICE * 100;
  } else if (invoice.shippingOpt.shippingType === 'express') {
    shippingPrice = +process.env.EXPRESS_SHIPPING_PRICE * 100;
  }

  if (shippingPrice > 0) {
    items.push({
      price_data: {
        currency: 'usd',
        product_data: {
          name: `Shipping (${invoice.shippingOpt.shippingType})`,
        },
        unit_amount: shippingPrice,
      },
      quantity: 1,
    });
  }

  const customerEmail = req?.user?.email || invoice.guestInfo.email;

  const session = await stripe.checkout.sessions.create({
    line_items: items,
    mode: 'payment',
    customer_email: customerEmail,
    success_url: `${process.env.APP_URL}/paymentSuccess?invoice=${invoice.id}`,
    cancel_url: `${process.env.APP_URL}/cart`,
  });

  await Invoice.findByIdAndUpdate(
    req.params.id,
    {
      checkoutSessionId: session.id,
    },
    { new: true }
  );

  if (invoice.coupon) {
    await Coupon.findByIdAndUpdate(invoice.coupon, {
      $inc: { usedCount: 1 },
    });
  }

  await sendCheckoutEmail(invoice);

  res.status(201).json({
    status: 'success',
    sessionUrl: session.url,
  });
});

exports.retrieveCheckoutAndUpdateInvoice = catchAsync(
  async (req, res, next) => {
    const { id } = req.params;
    if (!id) return next(new AppError('No invoice id provided', 400));

    const { checkoutSessionId } = await Invoice.findById(id);

    if (!checkoutSessionId)
      return next(new AppError('No checkout session found', 404));

    const session = await stripe.checkout.sessions.retrieve(checkoutSessionId);

    if (session.status !== 'complete')
      return next(new AppError('Payment failed', 402));

    const invoice = await Invoice.findByIdAndUpdate(
      id,
      { isPaid: true, status: 'complete' },
      { new: true, runValidators: true }
    );

    res.status(200).json({
      status: 'success',
      data: invoice,
    });
  }
);
