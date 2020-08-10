const multer = require('multer');

const MIME_TYPE_MAP = {
    'application/pdf': 'pdf',
    'application/octet-stream': 'djvu',
    'application/application/msword': 'doc',
    'application/vnd.openxmlformats-officedocument.wordprocessing': 'docx'
}

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const isValid = MIME_TYPE_MAP[file.mimetype];
        let error = 'Invalid mimetype.';
        if(!isValid) {
            return cb(error, false);
        }
        else if(isValid) {
            error = null;
            cb(error, "backend/books")
        }        
    },
    filename: (req, file, cb) => {
       const fileName = file.originalname;
       cb(null, fileName);
    }
}); 

module.exports = multer({storage: storage, preservePath: true}).single('book');
