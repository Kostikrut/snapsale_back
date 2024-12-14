const express = require('express');
const bannerController = require('../controllers/bannerController');
const authController = require('../controllers/authController');
const { uploadImageToS3Bucket } = require('../middlewares/s3ImageUpload');

const router = express.Router();

router.route('/').get(bannerController.getAllBanners);

router.use(authController.protect);

router.route('/').post(uploadImageToS3Bucket, bannerController.createBanner);

router
  .route('/:id')
  .put(uploadImageToS3Bucket, bannerController.updateBanner)
  .delete(bannerController.deleteBanner);

module.exports = router;
