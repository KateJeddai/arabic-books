const fs = require('fs');
const mongodb = require('mongodb');
const {ifAuth, ifAdmin, getUsername} = require('../middleware/authenticate');

// render books lists pages
const renderTutorialsPage = (req, res) => {    
    res.render('tutorials.hbs', { 
        holidays: req.hols,
        tutorials: req.tutorials,
        username: getUsername(req),
        loggedIn: ifAuth(req),
        ifAdmin: ifAdmin(req)
    });
}

const renderDictionariesPage = (req, res) => {
    res.render('dictionaries.hbs', { 
        holidays: req.hols,
        dictionaries: req.dictionaries,
        username: getUsername(req),
        loggedIn: ifAuth(req),
        ifAdmin: ifAdmin(req)
    });
}

const renderDialectsPage = (req, res) => {
    res.render('dialects.hbs', { 
        holidays: req.hols,
        dialects: req.dialects,
        username: getUsername(req),
        loggedIn: ifAuth(req),
        ifAdmin: ifAdmin(req)
    });
}

// get books lists
const getTutorials = (req, res, next) => {
    const db = req.app.locals.db;
    db.collection('tutorials.files').find().sort({filename:1}).toArray().then((tuts) => {
        req.tutorials = tuts;
        next();
    }).catch((err) => {
       res.status(400).send(e);
    });
}

const getDialects = (req, res, next) => {
    const db = req.app.locals.db;
    db.collection('dialects.files').find().sort({filename:1}).toArray().then((dits) => {
        req.dialects = dits;
        next();
    }).catch((err) => {
        res.status(400).send(e);
    });
}

const getDictionaries = (req, res, next) => {
    const db = req.app.locals.db;
    db.collection('dictionaries.files').find().sort({filename:1}).toArray().then((dicts) => {
        req.dictionaries = dicts;
        next();
    }).catch((err) => {
        res.status(400).send(e);
    });
}

// download a book
const downloadTutorial = (req, res) => {
    const name = req.params.name;    
    const db = req.app.locals.db;
    const bucket = new mongodb.GridFSBucket(db, {
        bucketName: 'tutorials'
    });  
        const stream = bucket.openDownloadStreamByName(name);
        stream.on('data', (chunk) => {
            res.write(chunk);
        })
        stream.on('end', () => {
            res.end();
        });
}

const downloadDictionary = (req, res) => {
    const name = req.params.name;    
    const db = req.app.locals.db;
    const bucket = new mongodb.GridFSBucket(db, {
        bucketName: 'dictionaries'
    });
   
    const stream = bucket.openDownloadStreamByName(name);
    stream.on('data', (chunk) => {
        res.write(chunk);
    })
    stream.on('end', () => {
        res.end();
    });
}

const downloadDialect = (req, res) => {
    const name = req.params.name;
    const db = req.app.locals.db;
    const bucket = new mongodb.GridFSBucket(db, {
        bucketName: 'dialects'
    });
    
    const stream = bucket.openDownloadStreamByName(name);
    stream.on('data', (chunk) => {
        res.write(chunk);
    })
    stream.on('end', () => {
        res.end();
    });
}

// upload a book
const moveFileToSubfolder = (from, to) => {
        const source = fs.createReadStream(from);
        const dest = fs.createWriteStream(to);
        return new Promise((resolve, reject) => {
            source.on('open', () => {
                source.pipe(dest);
            });
            source.on('end', ()  => {
                fs.unlink(from);
                resolve();
            });
            source.on('error', () => {
                reject(new Error('moving file failed'));
            });
        })
}

const uploadBookToGridBucket = (db, bucketName, pathToFile, fileName) => {
    const bucket = new mongodb.GridFSBucket(db, {
        bucketName: bucketName
    });   
    const source = fs.createReadStream(pathToFile); 
    return new Promise((resolve, reject) => {
        source.on('open', () => {
            source.pipe(bucket.openUploadStream(fileName));
        });
        source.on('end', ()  => {
            resolve();
        });
        source.on('error', () => {
            reject(new Error('moving file failed'));
        });
    })
}

const uploadBook = async (req, res) => {
    const db = req.app.locals.db;
    const {booksPicker} = req.body;
    if(req.file) {
        const fileName = req.file.filename;
        const oldPath = req.file.path;
        const newPath = `backend/books/${booksPicker}/${fileName}`;
        try {
            await moveFileToSubfolder(oldPath, newPath);
            await uploadBookToGridBucket(db, booksPicker, newPath, fileName);
            res.render('admin.hbs', {
                message: 'Upload successful.'
            });
        } catch(err) {
            res.render('admin.hbs', {
                message: err.message
            })
        }            
    } else {
        res.render('admin.hbs', {
            message: 'Upload failed.'
        })
    }   
}

// delete a book
const deleteBook = async (req, res, next) => {
    const db = req.app.locals.db;
    const {id, booktype} = req.params;
    const objectId = new mongodb.ObjectID(id); 
    try {
        await db.collection(booktype + '.files').deleteOne({'_id': objectId});
        await db.collection(booktype + '.chunks').deleteMany({'files_id': objectId});
        res.status(200).send('success');
    } catch(err) {
        res.render('error.hbs', {
            message: err.message
        })
    }
}

module.exports = {
    renderTutorialsPage,
    renderDictionariesPage,
    renderDialectsPage,
    getDictionaries, 
    getDialects, 
    getTutorials,
    downloadTutorial,
    downloadDictionary,
    downloadDialect,
    uploadBook,
    deleteBook
}
