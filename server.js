const mongoose = require('mongoose');
const dotenv = require('dotenv');
dotenv.config({ path: './config.env' });

// Catch uncaught exceptions if not handled
process.on('uncaughtException', (err) => {
  console.log('UNCAUGHT EXCEPTION! 💥 Shutting down...');
  console.log(err.name, err.message, err);
  process.exit(1);
});

const app = require('./app');

const DB = process.env.DATABASE.replace(
  '<PASSWORD>',
  process.env.DATABASE_PASSWORD
);

// Make a connection to mongoDB
mongoose
  .connect(DB, {
    useNewUrlParser: true,
    useCreateIndex: true,
    useFindAndModify: false,
    useUnifiedTopology: true,
  })
  .then((con) => console.log('Successfully connected to database'));

// Define port
const port = process.env.PORT || 3000;

// Run server
const server = app.listen(port, () =>
  console.log(`App is listening on port ${port}...`)
);

// Catch any unhandled promise rejection from the whole app
process.on('unhandledRejection', (err) => {
  console.log('UNHANDLED REJECTION! 💥 Shutting down...');
  console.log(err.name, err.message, err);
  // gracefull shutdown
  server.close(() => {
    process.exit(1);
  });
});
