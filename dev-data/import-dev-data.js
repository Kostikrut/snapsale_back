const fs = require('fs');
const mongoose = require('mongoose');
const dotenv = require('dotenv');

dotenv.config({ path: './config.env' });
const Listing = require('./../../models/listingModel');

const DB = process.env.DATABASE.replace(
  '<PASSWORD>',
  process.env.DATABASE_PASSWORD
);

mongoose
  .connect(DB, {
    useNewUrlParser: true,
    useCreateIndex: true,
    useFindAndModify: false,
    useUnifiedTopology: true,
  })
  .then((con) => console.log('Successfully connected to database'));

// Read data file
const listings = JSON.parse(
  fs.readFileSync(`${__dirname}/listings.json`, 'utf-8')
);

// Import data to DB
const importData = async function () {
  await Listing.create(listings, { runValidators: false });
  console.log('Data successfully loaded.');
};

// Delete all data from collection
const deleteData = async function () {
  await Listing.deleteMany();
  console.log('Data successfully deleted.');
};

if (process.argv[2] === '--import') {
  importData();
  // process.exit();
}

if (process.argv[2] === '--delete') {
  deleteData();
  // process.exit();
}
