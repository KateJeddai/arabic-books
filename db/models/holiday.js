const mongoose = require('mongoose');

const HolidaySchema = new mongoose.Schema({
  name: {
      type: String,
      required: true
  },
  country: {
      type: String,
      required: true
  },
  date: {
      type: String,
      required: true
  }
})

const Holiday = mongoose.model('Holiday', HolidaySchema);

module.exports = {
  Holiday
};
