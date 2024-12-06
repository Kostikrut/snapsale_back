const express = require('express');

const couponController = require('./../controllers/couponController');
const authController = require('./../controllers/authController');

const router = express.Router();

router
  .route('/')
  .post(
    authController.protect,
    authController.restrictTo('admin'),
    couponController.createCoupon
  )
  .get(
    authController.protect,
    authController.restrictTo('admin'),
    couponController.getAllCoupons
  );

router.route('/apply').post(couponController.applyCoupon);

router.post('/validate', couponController.validateCoupon);

router
  .route('/:code')
  .get(authController.restrictTo('admin'), couponController.getCoupon);

module.exports = router;
