var express = require('express');
var router = express.Router();
var bodyParser = require('body-parser');
var User = require('../user/User');

const {OAuth2Client} = require('google-auth-library');
const client = new OAuth2Client('184579261383-glto4fpim6hbor7u5973qoo473jt3ptm.apps.googleusercontent.com');

router.use(bodyParser.urlencoded({ extended: false }));
router.use(bodyParser.json());

var jwt = require('jsonwebtoken');
var bcrypt = require('bcryptjs');
var config = require('../config');

router.post('/register', function(req, res) {
  var hashedPassword = bcrypt.hashSync(req.body.password, 8);

  User.findOne({ email: req.body.email }, function(err, user) {
    if (err) return res.status(500).send("There was a problem registering the user.");

    if (user) return res.status(401).send({ auth: false, message: "Email has already exist" });

    User.create({
      username : req.body.username,
      email : req.body.email,
      password : hashedPassword
    },
    function (err, user) {
      if (err) return res.status(500).send("There was a problem registering the user.")
      // create a token
      var token = jwt.sign({ id: user._id }, config.secret, {
        expiresIn: 86400 // expires in 24 hours
      });
      res.status(200).send({ auth: true, token: token });
    });
  });
});

router.get('/me', function(req, res, next) {
  var token = req.headers['x-access-token'];
  if (!token) return res.status(401).send({ auth: false, message: 'No token provided.' });

  jwt.verify(token, config.secret, function(err, decoded) {
    if (err) return res.status(500).send({ auth: false, message: 'Failed to authenticate token.' });

    // res.status(200).send(decoded);
    User.findById(decoded.id, { password: 0 }, function(err, user) {
      if (err) return res.status(500).send("There was problem finding the user.");
      if (!user) return res.status(401).send({ auth: false, message: "No user found." });

      next(user);
    })
  });
});

router.use(function(user, req, res, next) {
  res.status(200).send(user);
})

router.post('/login', function(req, res) {
  if (req.body.email === '') return res.status(401).send({ auth: false, message: 'Username can not empty' })

  if (req.body.password === '') return res.status(401).send({ auth: false, message: 'Password can not empty' })

  User.findOne({ email: req.body.email }, function(err, user) {
    if (err) return res.status(500).send('Error on the server...');


    if (!user) return res.status(401).send({ auth: false, message: "No user found" });
    var passwordIsValid = bcrypt.compareSync(req.body.password, user.password);
    if (!passwordIsValid) return res.status(401).send({ auth: false, token: null, message: "password is not correct" });

    var token = jwt.sign({ id: user._id }, config.secret, {
      expiresIn: 86400 //exprires in 24 hours
    });

    res.status(200).send({ auth: true, token: token });
  });
});

router.get('/logout', function(req, res) {
  res.status(200).send({ auth: false, token: null });
});

router.post('/gg-login', async function(req, res) {
  const ticket = await client.verifyIdToken({
    idToken: req.body.token,
    audience: '184579261383-glto4fpim6hbor7u5973qoo473jt3ptm.apps.googleusercontent.com',
  });
  const payload = ticket.getPayload();
  const userid = payload['sub'];
  User.findOne({ email: payload['email'] }, function(err, user) {
    if (err) return res.status(500).send("There was a problem registering the user.");

    if (user) {
      const token = jwt.sign({ id: user._id }, config.secret, {
        expiresIn: 86400
      });
      res.status(200).send({ auth: true, token: token })
    } else {
      User.create({
        username : payload['name'],
        email : payload['email'],
        password: bcrypt.hashSync(userid, 8),
        profilePicture: payload['picture']
      },
      function (err, user) {
        // console.log(user)
        if (err) return res.status(500).send("There was a problem registering the user.")
        // create a token
        var token = jwt.sign({ id: user._id }, config.secret, {
          expiresIn: 86400 // expires in 24 hours
        });
        res.status(200).send({ auth: true, token: token });
      });
    }
  });
})

module.exports = router;