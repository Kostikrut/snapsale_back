const express = require('express');
const authController = require('./../controllers/authController');
const listingController = require('./../controllers/listingController');
const reviewRouter = require('./../routes/reviewRoutes');
const { uploadImageToS3Bucket } = require('../middlewares/s3ImageUpload');

const router = express.Router();

router
  .route('/')
  .get(listingController.getAllListings)
  .post(
    authController.protect,
    authController.restrictTo('maintainer', 'admin'),
    uploadImageToS3Bucket,
    listingController.createListing
  );

router.route('/getImagesUrls').post(listingController.getImagesUrls);

router.route('/loadHomePage').get(listingController.getThreeListingsByCategory);

router.route('/search').get(listingController.getSearchedListings);

router
  .route('/:id')
  .get(listingController.getListing)
  .patch(
    authController.protect,
    authController.restrictTo('maintainer', 'admin'),
    uploadImageToS3Bucket,
    listingController.updateListing
  )
  .delete(
    authController.protect,
    authController.restrictTo('maintainer', 'admin'),
    listingController.deleteListing
  );

router
  .route('/:id/variants')
  .patch(
    authController.protect,
    authController.restrictTo('maintainer', 'admin'),
    uploadImageToS3Bucket,
    listingController.updateListingVariant
  );

router.route('/:id/imgUrl').get(listingController.getListingImgUrl);

router.use('/:listingId/reviews', reviewRouter);

module.exports = router;
