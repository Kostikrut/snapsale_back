const fs = require('fs');
const mongoose = require('mongoose');
const dotenv = require('dotenv');

dotenv.config({ path: '../config.env' });

const Review = require('./../models/reviewModel');

const DB = process.env.DATABASE.replace(
  '<PASSWORD>',
  process.env.DATABASE_PASSWORD
);

(async () => {
  try {
    await mongoose.connect(DB);
    console.log('Successfully connected to database');

    const users = JSON.parse(
      fs.readFileSync(`${__dirname}/reviews.json`, 'utf-8')
    );

    const importData = async () => {
      await Review.create(users, { runValidators: false });
      console.log('Data successfully loaded.');
      process.exit();
    };

    const deleteData = async () => {
      await Review.deleteMany();
      console.log('Data successfully deleted.');
      process.exit();
    };

    if (process.argv[2] === '--import') {
      await importData();
    }

    if (process.argv[2] === '--delete') {
      await deleteData();
    }
  } catch (err) {
    console.error(err);
    process.exit(1);
  }
})();
