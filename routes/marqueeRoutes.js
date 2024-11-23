const express = require('express');

const authController = require('../controllers/authController');
const {
  createMarquee,
  updateMarquee,
  deleteMarquee,
  getAllMarquees,
} = require('../controllers/marqueeController');

const router = express.Router();

// router.use(authController.protect, authController.restrictTo('admin'));

router.route('/').get(getAllMarquees).post(createMarquee);
router.put('/:id', updateMarquee);
router.delete('/:id', deleteMarquee);

module.exports = router;
