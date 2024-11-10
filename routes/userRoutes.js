const express = require('express');
const userController = require('./../controllers/userController');
const authController = require('./../controllers/authController');
const { uploadImageToS3Bucket } = require('../middlewares/s3ImageUpload');

const router = express.Router();

router.post('/signup', authController.signup);
router.post('/login', authController.login);
router.post('/forgotPassword', authController.forgotPassword);
router.post(
  '/createUser', // Create a user with role property (Admin access only)
  authController.protect,
  authController.restrictTo('admin'),
  userController.createUser
);
router.patch('/resetPassword/:token', authController.resetPassword);

router.use(authController.protect);

router.get('/verifyStoredToken', authController.verifyStoredToken);
router.get('/me', userController.getMe, userController.getUser);
router.get('/purchaseHistory', userController.getPurchaseHistory);
router.patch('/updateMe', uploadImageToS3Bucket, userController.updateMe);
router.patch('/updateMyPassword', authController.updatePassword);
router.delete('/deleteMe', userController.deleteMe); // Deactivates the user

router.route('/').get(userController.getAllUsers); // admin access for user management (gets user "isActive" status)

router
  .route('/:id')
  .get(userController.getUser)
  .patch(
    authController.restrictTo('admin'),
    uploadImageToS3Bucket,
    userController.updateUser
  )
  .delete(authController.restrictTo('admin'), userController.deleteUser);

module.exports = router;
