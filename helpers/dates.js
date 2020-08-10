const moment = require('moment');
var moment_hijri = require('moment-hijri');

const getTodayDate = () => {
    const date = new Date();
    const options = { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' };
    return date.toLocaleDateString('en-EN', options);
}

const getTodayYear = () => {
    const date = new Date();
    return date.getFullYear();
}

const getTodayDateAr = () => {
    return moment().locale('ar').format('dddd Do MMMM YYYY');
}

const getHijriDate = () => {    
    return moment_hijri().format('iD iMMMM iYYYY');
}

module.exports = {
    getTodayDate, 
    getTodayYear,
    getTodayDateAr,
    getHijriDate
}
