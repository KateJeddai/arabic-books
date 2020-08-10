// cd../../Program Files/MongoDB/server/4.0/bin
require('./config/config.js');
const express = require('express');
const path = require('path');
const hbs = require('hbs');
const fs = require('fs');
const cors = require('cors');
const {mongoose} = require('./db/mongoose');
const _ = require('lodash');
const {checkUser, ifAuth, getUsername} = require('./middleware/authenticate');
const {getHolidays} = require('./controllers/holidays');
const {getTodayDate, getTodayYear, getTodayDateAr, getHijriDate} = require('./helpers/dates');

const app = express();
const port = process.env.PORT;  

const conn = mongoose.connection;
conn.on('connected', () => {
    console.log(process.env.MONGODB_URI);
    app.locals.db = conn.db;
})

app.use((req, res, next) => {
    res.header("Access-Control-Allow-Origin", "*"); 
    res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept, Authorization");
    res.header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
    res.header("Cache-Control", "no-cache, no-store, must-revalidate"); 
    next();
});

app.use(cors())

app.use(express.json({limit:'500mb'})); 
app.use(express.urlencoded({limit: "500mb", extended: true, parameterLimit:500000}));
app.use(express.static(path.join(__dirname, '/public')));

const auth = require('./routes/auth');
const books = require('./routes/books');
const holidays = require('./routes/holidays');
app.use('/auth', auth);
app.use('/books', books);
app.use('/holidays', holidays);

app.set('view engine', hbs);
hbs.registerPartial('header', fs.readFileSync(__dirname + '/views/partials/header.hbs', 'utf8'));
hbs.registerPartial('aside', fs.readFileSync(__dirname + '/views/partials/aside.hbs', 'utf8'));
hbs.registerPartial('footer', fs.readFileSync(__dirname + '/views/partials/footer.hbs', 'utf8'));
//hbs.registerPartials(path.join(__dirname, '/views/partials'));
hbs.registerHelper('getTodayDate', getTodayDate);
hbs.registerHelper('getTodayYear', getTodayYear);
hbs.registerHelper('getTodayDateAr', getTodayDateAr);
hbs.registerHelper('getHijriDate', getHijriDate);


// main page
app.get('/', getHolidays, checkUser, (req, res) => {
    res.render('arab.hbs', { 
        holidays: req.hols,
        username: getUsername(req),
        loggedIn: ifAuth(req)
    });
}, (err) => {
    res.status(400).send(err);
})

app.get('/links', getHolidays, checkUser, (req, res) => {
    res.render('links.hbs', { 
        holidays: req.hols,
        username: getUsername(req),
        loggedIn: ifAuth(req)
    });
}, (err) => {
    res.status(400).send(err);
})

// FOR ALL NON-EXISTING ROUTES
app.all('*', (req, res) => {
  res.redirect('/');
});

app.listen(port, () => {
    console.log(`App started on port ${port}`);
})

