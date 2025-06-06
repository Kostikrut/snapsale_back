const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const catchAsync = require('../utils/catchAsync');
const Invoice = require('../models/invoiceModel');
const Listing = require('../models/listingModel');
const Coupon = require('../models/couponModel');
const AppError = require('../utils/appError');
const { sendCheckoutEmail } = require('../utils/email');

const applyCoupon = async (invoice) => {
  if (!invoice.coupon) return { discount: 0, isFixed: false };

  const coupon = await Coupon.findById(invoice.coupon);
  if (!coupon) throw new AppError('Coupon not found', 404);

  const validation = await coupon.isValid(invoice);
  if (!validation.valid) throw new AppError(validation.message, 400);

  if (coupon.discountType === 'percentage') {
    return { discount: coupon.discountValue / 100, isFixed: false };
  }

  if (coupon.discountType === 'fixed') {
    return { discount: coupon.discountValue, isFixed: true };
  }

  throw new AppError('Unsupported coupon type', 400);
};

const buildLineItems = async (invoice, couponDiscount, isFixed) => {
  return Promise.all(
    invoice.listings.map(async (item) => {
      const listing = await Listing.findById(item._id);
      if (!listing) throw new AppError(`Listing ${item._id} not found`, 404);

      const title = `${listing.title} ${item.variants
        .map((v) => v.type)
        .join(' ')}`;

      const basePrice = item.variants.reduce(
        (acc, v) => acc + +v.price,
        +listing.price
      );

      const discount = basePrice * (item?.discount / 100 || 0);
      let finalPrice = basePrice - discount;

      if (isFixed) {
        const proportionalDiscount =
          couponDiscount * (finalPrice / invoice.total);
        finalPrice -= proportionalDiscount;
      } else {
        finalPrice *= 1 - couponDiscount;
      }

      return {
        price_data: {
          currency: 'usd',
          product_data: { name: title },
          unit_amount: Math.max(Math.round(finalPrice * 100), 0),
        },
        quantity: item.amount || 1,
      };
    })
  );
};

const getShippingLineItem = (shippingOpt) => {
  const type = shippingOpt.shippingType;
  let price = 0;

  if (type === 'standard') {
    price = +process.env.STANDARD_SHIPPING_PRICE;
  }

  if (type === 'express') {
    price = +process.env.EXPRESS_SHIPPING_PRICE;
  }

  if (price === 0) return null;

  return {
    price_data: {
      currency: 'usd',
      product_data: { name: `Shipping (${type})` },
      unit_amount: price * 100,
    },
    quantity: 1,
  };
};

exports.createCheckoutSession = catchAsync(async (req, res, next) => {
  const invoice = await Invoice.findById(req.params.id).populate('user');
  if (!invoice) return next(new AppError('Invoice not found', 404));

  const { discount: couponDiscount, isFixed } = await applyCoupon(invoice);

  const lineItems = await buildLineItems(invoice, couponDiscount, isFixed);

  const shippingItem = getShippingLineItem(invoice.shippingOpt);
  if (shippingItem) lineItems.push(shippingItem);

  const customerEmail = req?.user?.email || invoice.guestInfo.email;
  const session = await stripe.checkout.sessions.create({
    line_items: lineItems,
    mode: 'payment',
    customer_email: customerEmail,
    success_url: `${process.env.APP_URL}/paymentSuccess?invoice=${invoice.id}`,
    cancel_url: `${process.env.APP_URL}/cart`,
  });

  await Invoice.findByIdAndUpdate(req.params.id, {
    checkoutSessionId: session.id,
  });

  if (invoice.coupon) {
    await Coupon.findByIdAndUpdate(invoice.coupon, { $inc: { usedCount: 1 } });
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
