const Marquee = require('../models/marqueeModel');
const catchAsync = require('../utils/catchAsync');
const AppError = require('../utils/appError');

exports.getAllMarquees = catchAsync(async (req, res) => {
  const marquees = await Marquee.find();

  if (!marquees) return next(new AppError('No marquees found', 404));

  res.status(200).json({
    status: 'success',
    data: {
      marquees,
    },
  });
});

exports.createMarquee = catchAsync(async (req, res, next) => {
  const { marquee } = req.body;

  if (!marquee) return next(new AppError('No marquee data found', 400));

  const filterMarquee = {
    title: marquee.title,
    content: marquee.content,
    link: marquee.link,
  };

  const newMarquee = await Marquee.create(filterMarquee);

  res.status(201).json({
    status: 'success',
    data: {
      marquee: newMarquee,
    },
  });
});

exports.updateMarquee = catchAsync(async (req, res) => {
  const { id } = req.params;
  const { marquee } = req.body;

  if (!marquee) return next(new AppError('No marquee data found', 400));

  const filterMarquee = {
    title: marquee.title,
    content: marquee.content,
    link: marquee.link,
  };

  const updatedMarquee = await Marquee.findByIdAndUpdate(id, filterMarquee, {
    new: true,
    runValidators: true,
  });

  if (!updatedMarquee) return next(new AppError('No marquee found', 404));

  res.status(200).json({
    status: 'success',
    data: {
      marquee: updatedMarquee,
    },
  });
});

exports.deleteMarquee = catchAsync(async (req, res) => {
  const { id } = req.params;

  const deletedMarquee = await Marquee.findByIdAndDelete(id);

  if (!deletedMarquee) return next(new AppError('No marquee found', 404));

  res.status(204).json({
    status: 'success',
    data: null,
  });
});
