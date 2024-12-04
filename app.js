const express = require('express');
const path = require('path');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const mongoSanitize = require('express-mongo-sanitize');
const xss = require('xss-clean');
const hpp = require('hpp');
const cors = require('cors');
const compression = require('compression');
// const multer = require('multer');

// const { uploadImage, getImageUrl } = require('./utils/S3ImageUpload');
const AppError = require('./utils/appError');
const globalErrorHandler = require('./controllers/errorController');
const listingRouter = require('./routes/listingRoutes');
const userRouter = require('./routes/userRoutes');
const reviewRouter = require('./routes/reviewRoutes');
const invoiceRouter = require('./routes/invoiceRoutes');
const categoryRouter = require('./routes/categoryRoutes');
const marqueeRouter = require('./routes/marqueeRoutes');
const couponRouter = require('./routes/couponRoutes');

const app = express();

app.use('/uploads', cors(), express.static(path.join(__dirname, 'uploads')));

app.use(
  cors({
    origin: ['http://127.0.0.1:3000', process.env.APP_URL],
  })
);

app.get('/uploads/:image', (req, res) => {
  res.sendFile(__dirname + `/uploads/${req.params.image}`);
});

// Set security http headers
app.use(helmet());

// Dev logging
if (process.env.NODE_ENV === 'development') {
  app.use(morgan('dev'));
}

// Limit too many requests from the same API
const limiter = rateLimit({
  max: 3000,
  windowMs: 60 * 60 * 1000,
  message: 'To many requests from this IP, please try again in an hour.',
});
app.use('/api', limiter);

// Body parser - get the body from the request
app.use(express.json({ limit: '1mb' }));

app.use(express.urlencoded({ extended: true }));

// Data sanitization against noSQL query injection
app.use(mongoSanitize());

// Data sanitization against cross side scripting atacks - XSS
app.use(xss());

// Prevent parameter pollution - using only the last duplicate parameter
app.use(hpp());

app.use(compression());

app.use('/api/v1/listings', listingRouter);
app.use('/api/v1/users', userRouter);
app.use('/api/v1/reviews', reviewRouter);
app.use('/api/v1/invoices', invoiceRouter);
app.use('/api/v1/categories', categoryRouter);
app.use('/api/v1/marquees', marqueeRouter);
app.use('/api/v1/coupons', couponRouter);

app.all('*', (req, res, next) => {
  next(new AppError(`Can't find ${req.originalUrl} on this server!`, 404));
});

app.use(globalErrorHandler);

module.exports = app;
