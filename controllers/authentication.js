const jwt = require('jwt-simple');
const User = require('../models/user');
const config = require('../config');

// user model
function tokenForUser(user) {
  const timestamp = new Date().getTime();
  // sub = subject, iat = issued at time
  return jwt.encode({ sub: user.id, iat: timestamp }, config.secret);
}

exports.signin = function(req, res, next) {
  // User has already had their email and password auth'd
  // need to just give token
  res.send({ token: tokenForUser(req.user) });
}

exports.signup = function(req, res, next) {
  const email = req.body.email;
  const password = req.body.password;

  if(!email || !password) {
    return res.status(422).send({ error: 'You must provide email/password'});
  }
  // see if a user with the given email exists
  User.findOne({ email: email }, function(err, existingUser) {
    if(err) { return next(err); }

    // If a user with email does exist, return an error
    if(existingUser) {
      return res.status(422).send({ error: 'Email is in use'});
    }

    // if a user with email does not exist, create user
    const user = new User({
      email: email,
      password: password
    });

    // sync with the database and create the record
    user.save(function(err) {
      if(err) {return next(err);}
      // respond to request indicating the user was created
      res.json({ token: tokenForUser(user) });

    });
  });
}
