const {User} = require('../db/models/user');
const jwt = require('jsonwebtoken');

const authenticate = async (req, res, next) => {
    const regexToken = /token/;
    let token, cookiesArray;
    
    if(!regexToken.test(req.headers.cookie)) {
      res.redirect(`/auth/login?origUrl=${req.originalUrl}`);
    } else if(regexToken.test(req.headers.cookie)) {     
          if(req.headers.cookie.includes(';')) {
              cookiesArray = req.headers.cookie.split('; ').map(el => el.split('=').concat());
              cookiesArray.forEach(arr => {
                arr[0] === 'token' ? token = arr[1] : token = token;
              })
          } else if(!req.headers.cookie.includes(';')) {
              cookiesArray = req.headers.cookie.split('=');          
              token = cookiesArray[1];
          }
          try {     
            const user = await User.findByToken(token);
            if(!user) {
                res.redirect('/auth/login');
            }              
            req.user = user;  
            req.token = token;
            next();     
          } catch(err) {
              if(err === 'Token is expired') { 
                 res.redirect('/auth/login');
              } else {
                 throw new Error('Authentication failed.');
              }
          }
    }     
}   	

const authenticateAdmin = async (req, res, next) => {  
    const regexToken = /token/;
    let token, cookiesArray;    
    if(!regexToken.test(req.headers.cookie)) {
      res.redirect('/auth/admin-login');
    } else if(regexToken.test(req.headers.cookie)) {     
          if(req.headers.cookie.includes(';')) {
              cookiesArray = req.headers.cookie.split('; ').map(el => el.split('=').concat());
              cookiesArray.forEach(arr => {
                arr[0] === 'token' ? token = arr[1] : token = token;
              })
          } else if(!req.headers.cookie.includes(';')) {
              cookiesArray = req.headers.cookie.split('=');          
              token = cookiesArray[1];
          } 
          try {
            const role = jwt.verify(token, process.env.JWT_SECRET).access,
                  id = jwt.verify(token, process.env.JWT_SECRET)._id;
                  if(role === 'admin') {                    
                      const user = await User.findOne({_id: id});
                      if(!user) {
                        res.redirect('/auth/admin-login');
                      }  
                      req.user = user;
                      req.token = token;
                      next(); 
                  } else {
                      res.redirect('/auth/admin-login');
                  }
          } catch(err) {
              if(err === 'Token is expired') { 
                res.redirect('/auth/admin-login');
              } else {
                  throw new Error('Admin authentication failed.');
              }
          }
    }   
}

const checkUser = async (req, res, next) => {
    const regexToken = /token/;
    let token, cookiesArray;
  
    if(!regexToken.test(req.headers.cookie)) {   
      next();
    } else if (regexToken.test(req.headers.cookie)) {      
          if(req.headers.cookie.includes(';')) {
              cookiesArray = req.headers.cookie.split('; ').map(el => el.split('=').concat());
              cookiesArray.forEach(arr => {
                arr[0] === 'token' ? token = arr[1] : token = token;
              })
          } else if(!req.headers.cookie.includes(';')) {
              cookiesArray = req.headers.cookie.split('=');          
              token = cookiesArray[1];
          }
          try {
              const id = await jwt.verify(token, process.env.JWT_SECRET)._id;
              const user = await User.findOne({_id: id});
              if(!user) {
                next();
              } 
              req.user = user;  
              next();     
          } catch(err) {
              console.log('errrrr', err);
              next();
          }
    } else {
        next();
    }
}

const ifAuth = (req) => {
  return req.user && req.user.tokens[0] && req.user.tokens[0].token ? true : false;
}

const ifAdmin = (req) => {
  if(req.user) {
    const role = jwt.verify(req.user.tokens[0].token, process.env.JWT_SECRET).access;
    return role === 'admin';
  } else {
    return false;
  }
}

const getUsername = (req) => {
  return req.user && req.user && req.user.tokens[0] ? req.user.username : null;
}

module.exports = {authenticate, authenticateAdmin, checkUser, ifAuth, ifAdmin, getUsername};
