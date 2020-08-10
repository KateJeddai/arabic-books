const validator = require('validator');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const mongoose = require('mongoose');

const UserSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true
  },
  email: {
    type: String,
    required: true,
    trim: true,
    unique: true,
    validate: {
          validator: validator.isEmail,
          message: '{VALUE} is not a valid email'
        }
  },
  password: {
    type: String,
    required: true,
    minlength: 8,
    validate: {
      validator: function(v) {
    	   return /^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$%^&*-]).{8,}$/.test(v)
      },
      message: 'Password must be at least 8 characters length and include at least: one uppercase character, one lowercase character, one number and a special character'
    }  
  },
  tokens: [{
        access: {
            type: String
        },
        token: {
            type: String
        }
  }],
  verified: {
    type: Boolean,
    required: true,
    default: false
  },
  confirmToken: {
    type: String
  },
  admin: {
    type: Boolean,
    default: false
  }  
});

UserSchema.methods.generateAuthToken = function() {
	  var user = this,    
        access = 'auth',
        token = jwt.sign({ _id: user._id.toHexString(), access}, process.env.JWT_SECRET, { expiresIn: '3h' }).toString();
    const tokens = [{access, token}];   
    return User.updateOne({ email: user.email }, { '$set': { tokens }})
               .then(() => {                 
                   return token;
              }).catch((e) => {
                   console.log(e);
                   return;
              })
}

UserSchema.methods.removeToken = async function(token) {
  const user = this;
  await user.updateOne({ $set: { tokens: []}});   
  const updatedUser = await User.findById(user.id);
  return updatedUser;
}

UserSchema.statics.findByToken = function(token) {
    const User = this;
    var decoded;
    try {
    	decoded = jwt.verify(token, process.env.JWT_SECRET);  
    } catch (e) {
        if(e.name === 'TokenExpiredError') {
           return Promise.reject('Token is expired');
        }
        return Promise.reject('User is unauthorized');
    }
    return User.findOne({
    	_id: decoded._id,
    	'tokens.token': token,
      'tokens.access': decoded.access
    })
}

UserSchema.statics.findByCredentials = function(email, password) {
  const User = this;
	return User.findOne({email}).then((user) => {
    if(!user) {
          return Promise.reject("Email or password is incorrect.");
		}
    return new Promise((resolve, reject) => {
            bcrypt.compare(password, user.password, (err, res) => {
            	if(res) {
                resolve(user);
            	} else {
            		reject("Email or password is incorrect.");
            	}
            })
		})
	})
}

UserSchema.pre('save', function(next) {
	const user = this;
	if(user.isModified('password')) {
      bcrypt.genSalt(10, (err, salt) => {
      	bcrypt.hash(user.password, salt, (err, hash) => {
      		user.password = hash;
      		next();
      	})
      })
	} 
})

const User = mongoose.model('User', UserSchema);

module.exports = {User};

