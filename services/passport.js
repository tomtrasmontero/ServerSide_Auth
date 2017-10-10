const passport = require('passport');
const User = require('../models/user');
const config = require('../config');
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const LocalStrategy = require('passport-local');

// create local strategy
// default strategy expect to receive username and password.  App is using email
// and password so we need to specify the usernameField will be 'email' and not username
const localOptions = { usernameField: 'email'};
const localLogin = new LocalStrategy(localOptions, function(email, password, done) {
  // Verify this username and password, call done with the user name
  // if it is the correct username and password, otherwise call done with false
  User.findOne({ email: email}, function(err, user) {
    if(err) { return done(err);}
    // if user is not found return false without err obj
    if (!user) { return done(null, false);}

    // compare passwords - is 'password' equal to user.password?
    user.comparePassword(password, function(err, isMatch) {
      if (err) { return done(err); }
      if (!isMatch) { return done(null, false); }

      return done(null, user);
    })
  })
});

// setup options for JWT Strategy, where to find the jwt token
const jwtOptions = {
  jwtFromRequest: ExtractJwt.fromHeader('authorization'),
  secretOrKey: config.secret
};

// create JWT Strategy.
const jwtLogin = new JwtStrategy(jwtOptions, function(payload, done) {
  // see if the user ID in the payload exists in our db
  // If it does, call 'done' with that , otherwise call done without a user object
  User.findById(payload.sub, function(err, user) {
    // there is an error and did not find a user
    if (err) { return done(err, false); }

    if (user) {
      // found a user
      done(null, user);
    } else {
      // did not find any user
      done(null, false);
    }

  });
});

// tell passport to use this strategy
passport.use(jwtLogin);
passport.use(localLogin);
