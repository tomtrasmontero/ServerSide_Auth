const Authentication = require('./controllers/authentication');
const passportService = require('./services/passport');
const passport = require('passport');

// session false = do not create cookies, we are using token
const requireAuth = passport.authenticate('jwt', { session: false });
const requireSignin = passport.authenticate('local', { session: false });

module.exports = function(app) {
  app.get('/', requireAuth, function(req, res) {
    res.send({ hi: 'there'});
  });

  app.post('/singin', requireSignin, Authentication.signin)

  // routes hitting the signup will have the Authentication.signup
  // function will be ran
  app.post('/signup', Authentication.signup);
}
