const express = require('express');
const router = express.Router();
const {authenticateAdmin} = require('../middleware/authenticate');
const {uploadHoliday} = require('../controllers/holidays');

// upload a holiday
router.post('/upload-holiday', authenticateAdmin, uploadHoliday);

module.exports = router;
