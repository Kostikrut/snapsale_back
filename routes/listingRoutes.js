const express = require('express');
const authController = require('./../controllers/authController');
const listingController = require('./../controllers/listingController');
const reviewRouter = require('./../routes/reviewRoutes');

const router = express.Router();

router
  .route('/')
  .get(listingController.getAllListings)
  .post(
    authController.protect,
    authController.restrictTo('maintainer', 'admin'),
    listingController.createListing
  );

router
  .route('/:id')
  .get(listingController.getListing)
  .patch(
    authController.protect,
    authController.restrictTo('maintainer', 'admin'),
    listingController.updateListing
  )
  .delete(
    authController.protect,
    authController.restrictTo('maintainer', 'admin'),
    listingController.deleteListing
  );

router.use('/:listingId/reviews', reviewRouter);

module.exports = router;
