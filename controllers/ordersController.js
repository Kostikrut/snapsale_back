const dotenv = require('dotenv');
const catchAsync = require('../utils/catchAsync');
const Invoice = require('./../models/invoiceModel');
const User = require('./../models/userModel');
const AppError = require('./../utils/appError');

dotenv.config({ path: './config.env' });
const { PAYPAL_CLIENT_ID, PAYPAL_CLIENT_SECRET } = process.env;
const base = 'https://api-m.sandbox.paypal.com';

const generateAccessToken = async () => {
  try {
    if (!PAYPAL_CLIENT_ID || !PAYPAL_CLIENT_SECRET) {
      throw new Error('MISSING_API_CREDENTIALS');
    }
    const auth = Buffer.from(
      PAYPAL_CLIENT_ID + ':' + PAYPAL_CLIENT_SECRET
    ).toString('base64');
    const response = await fetch(`${base}/v1/oauth2/token`, {
      method: 'POST',
      body: 'grant_type=client_credentials',
      headers: {
        Authorization: `Basic ${auth}`,
      },
    });

    const data = await response.json();
    return data.access_token;
  } catch (error) {
    console.error('Failed to generate Access Token:', error);
  }
};

const createOrder = async (cart) => {
  const accessToken = await generateAccessToken();
  const url = `${base}/v2/checkout/orders`;
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

  return handleResponse(response);
};

const captureOrder = async (orderID) => {
  const accessToken = await generateAccessToken();
  const url = `${base}/v2/checkout/orders/${orderID}/capture`;

  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${accessToken}`,
    },
  });

  return handleResponse(response);
};

async function handleResponse(response) {
  try {
    const jsonResponse = await response.json();
    return {
      jsonResponse,
      httpStatusCode: response.status,
    };
  } catch (err) {
    const errorMessage = await response.text();
    throw new Error(errorMessage);
  }
}

exports.placeOrder = catchAsync(async (req, res, next) => {
  const cart = await Invoice.findById(req.params.id);
  const { jsonResponse, httpStatusCode } = await createOrder(cart);

  if (!httpStatusCode || !jsonResponse) {
    return next(new AppError('Failed to create order.', 500));
  }

  return res.status(httpStatusCode).json(jsonResponse);
});

exports.catchOrder = catchAsync(async (req, res, next) => {
  const { orderID, id: invoiceID } = req.params;
  const { jsonResponse, httpStatusCode } = await captureOrder(orderID);

  // console.log(req.user.id);

  if (!jsonResponse || !httpStatusCode)
    return next(new AppError('Failed to capture order.', 500));

  if (jsonResponse?.status === 'COMPLETED') {
    await Invoice.updateOne(
      { _id: invoiceID },
      { status: 'approved', isPaid: true }
    );
  }

  if (jsonResponse?.name === 'UNPROCESSABLE_ENTITY') {
    await Invoice.updateOne(
      { _id: invoiceID },
      { status: 'canceled', isPaid: false }
    );
  }

  return res.status(httpStatusCode).json(jsonResponse);
});
