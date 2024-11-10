const express = require('express');
const invoiceController = require('./../controllers/invoiceController');
const authController = require('./../controllers/authController');
const checkoutController = require('../controllers/checkoutController');

const router = express.Router();

router
  .route('/:id/retrieveCheckoutAndUpdateInvoice')
  .get(checkoutController.retrieveCheckoutAndUpdateInvoice);

router.use(authController.protect);

router
  .route('/getPurchaseHistory')
  .get(
    invoiceController.getInvoiceUserId,
    invoiceController.getPurchaseHistory
  );

router
  .route('/')
  .post(invoiceController.getInvoiceUserId, invoiceController.createInvoice);

router
  .route('/:id')
  .get(authController.restrictTo('admin', 'user'), invoiceController.getInvoice)
  .delete(authController.restrictTo('admin'), invoiceController.deleteInvoice);

router
  .route('/:id/createCheckoutSession')
  .post(checkoutController.createCheckoutSession);

router

  .route('/:id/updateAddressAndShipping')
  .patch(
    invoiceController.getInvoiceUserId,
    invoiceController.updateAddressAndShipping
  );

module.exports = router;
