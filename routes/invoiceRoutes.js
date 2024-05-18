const express = require('express');
const invoiceController = require('./../controllers/invoiceController');
const authController = require('./../controllers/authController');
const ordersController = require('./../controllers/ordersController');

const router = express.Router();

router
  .route('/')
  .get(
    authController.protect,
    authController.restrictTo('admin', 'user'),
    invoiceController.getInvoice
  )
  .post(
    authController.protect,
    invoiceController.getInvoiceUserId,
    invoiceController.createInvoice
  );

router
  .route('/:id')
  .delete(
    authController.protect,
    authController.restrictTo('admin'),
    invoiceController.deleteInvoice
  );

router
  .route('/:id/orders')
  .post(authController.protect, ordersController.placeOrder);
router
  .route('/:id/orders/:orderID/capture')
  .post(authController.protect, ordersController.catchOrder);

module.exports = router;
