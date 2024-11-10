const express = require('express');
const categoryController = require('./../controllers/categoryController');
const authController = require('./../controllers/authController');
const { uploadImageToS3Bucket } = require('../middlewares/s3ImageUpload');

const router = express.Router();

router.route('/').get(categoryController.getCategories);

router.use(authController.protect);
router.use(authController.restrictTo('admin'));

router
  .route('/')
  .patch(uploadImageToS3Bucket, categoryController.updateList)
  .delete(categoryController.deleteFromList);

module.exports = router;
