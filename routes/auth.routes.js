// routes/auth.routes.js
const express = require('express');
const { Router } = require('express');
const router = new Router();
const bcryptjs = require('bcryptjs');
const saltRounds = 10;
const User = require('../models/User.model');
const { isLoggedIn, isLoggedOut } = require('../middleware/isLogged.js');

// GET route ==> to display the signup form to users
router.get('/signup', (req, res) => res.render('auth/signup'));

// POST route ==> to process form data
router.post('/signup', (req, res, next) => {
    // console.log("The form data: ", req.body);
   
    const { username, email, password } = req.body;
   
    bcryptjs
      .genSalt(saltRounds)
      .then(salt => bcryptjs.hash(password, salt))
      .then(hashedPassword => {
        return User.create({
          username,
          email,
          passwordHash: hashedPassword
        });
      })
      .then(userFromDB => {
        console.log('Newly created user is: ', userFromDB);
        res.redirect('/userProfile');
      })
      .catch(error => next(error));
  });

router.get('/userProfile', (req, res) => res.render('users/user-profile'));



router.get('/login', isLoggedOut, (req, res) => res.render('auth/login'));


router.post('/login', isLoggedOut, (req, res, next) => {
  console.log('SESSION =====> ', req.session);

  const { username, password } = req.body;
 
  if (username === '' || password === '') {
    res.render('auth/login', {
      errorMessage: 'Please enter username and password to login.'
    });
    return;
  }
 
  User.findOne({ username })     
    .then(user => {     
                       
      if (!user) {      
        res.render('auth/login', { errorMessage: 'Username is not registered. Try with other username.' });
        return;
      } 
      
        else if (bcryptjs.compareSync(password, user.passwordHash)) {
      
        req.session.user = user;
        res.redirect('/userProfile');
      } else {
      
        res.render('auth/login', { errorMessage: 'Incorrect password.' });
      }
    })
    .catch(error => next(error));  
});

router.post('/logout', isLoggedIn, (req, res, next) => {
  req.session.destroy(err => {
    if (err) next(err);
    res.redirect('/');
  });
});


router.get('/userProfile', isLoggedIn, (req, res) => {
  res.render('users/user-profile', { userInSession: req.session.user });
});

module.exports = router;
