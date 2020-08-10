const _ = require('lodash');
const jwt = require('jsonwebtoken');
const {User} = require('../db/models/user');
const {ifAuth, getUsername} = require('../middleware/authenticate');
const {sendMail} = require('../confirmemail');

// ADMIN
const renderAdminLoginPage = (req, res, next) => {
    if(ifAuth(req)) {
        res.redirect('/');
    }
    res.render('admin-login.hbs');
} 

const renderAdminPanel = (req, res, next) => {
    res.render('admin.hbs', {
        loggedIn: ifAuth(req)
    });
}

const addAdmin = async (req, res) => {
    var body = _.pick(req.body, ['username', 'email', 'password']);
    const user = new User({
        username: body.username,
        email: body.email,
        password: body.password,
        admin: true,
        verified: true
    });
    try {
        await user.save();
        res.redirect('/auth/admin');
    } catch(err) {
        res.render('admin.hbs', {
            message: err.message,
            loggedIn: ifAuth(req)
        });
    }
}

const adminLogin = async (req, res, next) => {
    var body = _.pick(req.body, ['email', 'password']);  
    try {
      let user = await User.findByCredentials(body.email, body.password);
      if(user && user.admin) {
        const access = 'admin',
        token = jwt.sign({ _id: user._id.toHexString(), access}, process.env.JWT_SECRET, { expiresIn: '3h' }).toString(),
        tokens = [{access, token}];

        await User.updateOne({ email: user.email }, { '$set': { tokens }}); 
        const expiryDate = new Date(Date.now() + 3 * 60 * 60 * 1000)   
        res.cookie('token', token, { httpOnly: true, expires: expiryDate });
        res.cookie('username', user.username, { httpOnly: true, expires: expiryDate });           
        res.redirect('/auth/admin');
      }
      else {
          throw new Error('User doesn\'t have admin rights');
      }
    }
    catch (err) {
       res.render('admin-login.hbs', {
           message: err
       });
    }
}

// USERS AUTHENTICATION
// render pages 
const renderSignupPage = (req, res) => {
    if(ifAuth(req)) {
       res.redirect('/');
    }  
    res.render('signup.hbs');
}

const renderLoginPage = (req, res) => {
    const origUrl = req.query.origUrl && req.query.origUrl.split(' ').join('+');
    console.log(req.user)
    if(ifAuth(req)) {
        res.redirect('/');
    }
    res.render('login.hbs', {
        message: req.query.message ? req.query.message : null,
        origUrl: origUrl
    });
}

const renderRestorePassPage = (req, res) => {
    res.render('restore-pass.hbs');
}

const renderResetForm = async (req, res) => {    
    const confirmToken = req.query.token;  
    try {        
        const decoded = jwt.verify(confirmToken, process.env.JWT_SECRET);
        const user = await User.findOne({confirmToken});
        res.cookie('token', confirmToken, { httpOnly: true });
        res.render('reset-form.hbs');        
    } catch(err) {
        if(err.message === 'jwt expired') {
            res.render('restore-pass.hbs', {
                message: "The link has expired.",
                id: user._id 
            });
        } else {
            res.render('restore-pass.hbs', {
                message: err.message
            })
        }
    }
}

// signup a new user 
const signupUser = async (req, res) => {
    const body = _.pick(req.body, ['username', 'email', 'password', 'copypassword']);  
    const form = {
        usernameholder: body.username,
        emailholder: body.email
    };
    const user = new User(body);
          user.verified = false;
          user.confirmToken = jwt.sign({username: user.username}, 
                                        process.env.JWT_SECRET, 
                                       {expiresIn: '24h'}).toString();
    try {
        await user.save();
        const link = "http://" + req.get('host') + "/auth/verify?token=" + user.confirmToken;
        const htmlMsg = "Please, click on the link to verify your email.<br><a href=" + link + ">Click here to verify</a>";
        sendMail(user, htmlMsg);
        res.render('signup.hbs', {
            message: 'Please, check your email for a confirmation link!',
            id: user._id
        });
    } catch(err){
        if(err.name === 'MongoError') {
            const formData = {username: '', email: ''};
            if((RegExp('username')).test(err.errmsg) && (RegExp('duplicate')).test(err.errmsg)) {
                formData.username = 'Username is already in use';
            }  
            if((RegExp('email')).test(err.errmsg) && (RegExp('duplicate')).test(err.errmsg)) {
                formData.email = 'Email is already in use';
            }
            res.render('signup.hbs', {
                errors: err,  
                formData,
                form
            })
        }
        else { 
            res.render('signup.hbs', {
                errors: err,
                formData: {
                    username: err.toJSON().errors['username'] ? err.toJSON().errors['username'].message : null,
                    email: err.toJSON().errors['email'] ? err.toJSON().errors['email'].message : null,
                    password: err.toJSON().errors['password'] ? err.toJSON().errors['password'].message : null
                },
                form
            });
        }
    }   
}

// verify user's email
const verifyEmail = async (req, res) => {
    if(ifAuth(req)) {
        res.render('login.hbs', {
            loggedinMsg: "You've already logged in.",
            username: getUsername(req),
            loggedIn: ifAuth(req)
        });
    } else {
        const confirmToken = req.query.token;
        const user = await User.findOne({confirmToken});
        if(!user) {
            res.render('signup.hbs', {
                message: "User not found."
            });
        }
        try {
            const decoded = jwt.verify(confirmToken, process.env.JWT_SECRET);        
            await User.updateOne({ email: user.email }, { '$set': { verified: true }});                   
            res.render('login.hbs', {
               confirmation: 'Your email has been confirmed.'
            });
        } catch(err) {
            if(err.message === 'jwt expired') {
                res.render('signup.hbs', {
                    message: "Confirmation link has expired.",
                    id: user._id 
                });
            } else {
                res.render('signup.hbs', {
                    message: err.message
               })
            }          
        }
    } 
} 

// resend link to verify email
const resendLinkToVerify = async (req, res) => {
    const id = req.query.user;
    try{
      const user = await User.findOne({_id: id});
      const confirmToken = jwt.sign({username: user.username}, 
                                    process.env.JWT_SECRET, 
                                    { expiresIn: '24h' }).toString();
      await User.updateOne({_id: id}, { '$set': { confirmToken }});
      const link = "http://" + req.get('host') + "/auth/verify?token=" + confirmToken;
      const htmlMsg = "Please, click on the link to verify your email.<br><a href=" + link + ">Click here to verify</a>";
            sendMail(user, htmlMsg);        
            res.render('signup.hbs', {
              message: 'Please, check your email for a confirmation link!',
              id: user._id
            });
             
    } catch(err) {
        res.render('signup.hbs', {
              message: 'Something went wrong. Try again later.'
        });
    }
}

// login user 
const loginUser = async (req, res) => {
    var body = _.pick(req.body, ['email', 'password']);
    try {
      const user = await User.findByCredentials(body.email, body.password);
      if(user && user.verified) {
        const token = await user.generateAuthToken(); 
        const expiryDate = new Date(Date.now() + 3 * 60 * 60 * 1000);
        res.cookie('token', token, { httpOnly: true, expires: expiryDate });
        res.cookie('username', user.username, { httpOnly: true, expires: expiryDate });
    
        if(req.body.origUrl) {
            const origUrl = req.body.origUrl.split('+').join(' ');
            res.redirect(origUrl);
        }
        res.redirect('/');
      }  
      else if(user && !user.verified){
         res.redirect('/auth/login?message=Email is not verified. Check your email for a verification link.');
      } 
    } catch (e) {
        res.redirect('/auth/login?message=' + e);
    }
}

// signout user
const signoutUser = async (req, res) => {
    try {
        const user = await req.user.removeToken(req.token); 
        res.clearCookie('token');
        res.clearCookie('username');
        res.redirect('/');
    } catch(err) {
        res.render('error.hbs', {
            message: err.message
        });
    }
}

// restore password
const sendEmailToRestorePass = async (req, res) => {
    const email = req.body.email;
    try {
        const user = await User.findOne({email});
        if(!user) {
            res.render('restore-pass.hbs', {
                message: 'User with such email doesn\'t exist.'
            });
        } else {
            const confirmToken = jwt.sign({_id: user._id.toHexString()}, 
                                           process.env.JWT_SECRET, 
                                           { expiresIn: '24h' }).toString();
            await User.updateOne({email}, { '$set': { confirmToken }});
            const link = "http://" + req.get('host') + "/auth/reset-form?token=" + confirmToken;
            const htmlMsg = "To create a new password, please follow the link below.<br><a href=" + link + ">Click here.</a>";
            sendMail(user, htmlMsg);
            res.render('restore-pass.hbs', {
                message: 'Instruction how to change your password was sent to your email.'
            });
        }        
    } catch(err) {
        res.render('restore-pass.hbs', {
            message: err
        });
    }
}

const resetPass = async (req, res) => {
    const {password} = req.body;
    const confirmToken = req.user.confirmToken;
    try {  
        const user = await User.findOne({confirmToken});
        user.password = password;
        await user.save();
        res.render('restore-pass.hbs', {
            message_change: 'The password has been changed.' 
        });
    } catch(err) {
        res.render('restore-pass.hbs', {
            message: err
        });
    }
}

module.exports = {
    renderAdminLoginPage,
    renderAdminPanel,
    addAdmin,
    adminLogin,
    renderSignupPage,
    renderLoginPage,
    renderRestorePassPage,
    renderResetForm,
    signupUser,
    verifyEmail,
    resendLinkToVerify,
    loginUser,
    signoutUser,
    sendEmailToRestorePass,
    resetPass
}
