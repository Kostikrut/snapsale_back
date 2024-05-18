const express = require('express');
const authController = require('./../controllers/authController');
const reviewController = require('./../controllers/reviewController');

const router = express.Router({ mergeParams: true });

router.use(authController.protect);

router.route('/').get(reviewController.getAllReviews);

router
  .route('/:id')
  .post(
    authController.restrictTo('user'),
    reviewController.getListingUserIds,
    reviewController.createReview
  )
  .get(reviewController.getReview)
  .patch(authController.restrictTo('user'), reviewController.updateReview)
  .delete(
    authController.restrictTo('moderator', 'admin', 'user'),
    reviewController.deleteReview
  );

module.exports = router;
