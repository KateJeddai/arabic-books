const {Holiday} = require('../db/models/holiday');

// get holidays for today
const getHolidays = async (req, res, next) => {
    try {
        let holidays = await Holiday.find();
        let mm = new Date().getMonth();
        let months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
        let monthNow = months[mm];
        let dd = new Date().getDate();  
        holidays = holidays.filter(hol => hol.date.split(' ')[1] == monthNow && 
                                          hol.date.split(' ')[0] == dd);
        req.hols = holidays;
        next(); 
    } catch(err) {
		res.render('error.hbs', {
            message: err.message
        });
	}
}

// upload a holiday
const uploadHoliday = async (req, res) => {
    const {name, country, date} = req.body;
    console.log(name, country, date);
    let holiday = new Holiday({
                    name,
                    country,
                    date
                });
    try {
        await holiday.save();
        res.redirect('/auth/admin');
    } catch(err) {
        res.render('error.hbs', {
            message: err.message
        });
    }
}

module.exports = {
    getHolidays,
    uploadHoliday
}
