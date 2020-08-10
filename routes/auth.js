const express = require('express');
const router = express.Router();
const {authenticate, authenticateAdmin, checkUser} = require('../middleware/authenticate');
const {renderAdminLoginPage, renderAdminPanel, adminLogin, addAdmin,
       renderSignupPage, renderLoginPage, renderRestorePassPage, renderResetForm,
       signupUser, verifyEmail, resendLinkToVerify, loginUser, signoutUser,
       sendEmailToRestorePass, resetPass} = require('../controllers/auth');

//ADMIN
router.get('/admin', authenticateAdmin, renderAdminPanel, (err) => {
    res.render('error.hbs', {
        message: err.message
    });
})

router.get('/admin-login', checkUser, renderAdminLoginPage);

router.post('/admin/add', authenticateAdmin, addAdmin);

router.post('/admin/login', adminLogin);

// USER SIGNUP AND LOGIN 
router.get('/signup', checkUser, renderSignupPage, (err) => {
    res.render('error.hbs', {
        message: err.message
    });
})

router.get('/login', checkUser, renderLoginPage, (err) => {
    console.log(req.user)
    res.render('error.hbs', {
        message: err.message
    });
})

router.post('/users', signupUser);

router.get('/verify', checkUser, verifyEmail);

router.get('/resend', resendLinkToVerify);

router.post('/users/login', loginUser);

router.get('/signout', authenticate, signoutUser);

// RESET PASSWORD 
router.get('/restore-password', renderRestorePassPage, (err) => {
    res.render('error.hbs', {
        message: err.message
    }); 
})

router.post('/restore', sendEmailToRestorePass);

router.get('/reset-form', renderResetForm);

router.post('/reset-pass', checkUser, resetPass);

module.exports = router;
