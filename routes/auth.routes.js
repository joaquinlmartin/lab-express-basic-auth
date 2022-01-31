const { Router } = require('express');
const router = new Router();
// const mongoose = require('mongoose');

const bcryptjs = require('bcryptjs');
const saltRounds = 20;
const User = require('../models/User.model');
const { isLoggedIn } = require('../middlewares');

router.get('/signup', (req, res) => {
  res.render('auth/signup')
})

router.post('/signup', (req, res, next) => {
  const { username, password } = req.body;
  if (!username || !password) {
    res.render('signup', {
      errorMessage: "Put your username and your password"
    })
  }
  bcryptjs
    .genSalt(saltRounds)
    .then(salt => bcryptjs.hash(password, salt))
    .then(hashedPassword => {
      console.log(`Password hash: ${hashedPassword}`);
      return User.create({
        username,
        password: hashedPassword
      })
    })
    .then(userFromDB => {
      console.log(`New user ${userFromDB} is created`);
      res.redirect('auth/login')
    })
    .catch(error => next(error));
})

router.get('/login', (req, res, next) => {
  res.render('auth/login');
});

router.post('/login', async (req, res, next) => {
  const { username, password } = req.body;
  if (username === '' || password === '') {
    return res.render('auth/login', { errorMessage: 'Enter correct user and password' });
  }

  try {
    const user = await User.findOne({ username });

    if (!username) {
      return res.render('auth/login', { errorMessage: 'User not found' });
    }
    if (bcryptjs.compareSync(password, user.hashedPassword)) {
      req.session.currentUser = {
        _id: user._id,
        username: user.username,
      };
      return res.redirect('/');
    }
    return res.render('auth/login', { errorMessage: 'Incorrect password' });
  } catch (e) {
    next(e);
  }
});

router.post('/logout', (req, res, next) => {
  req.session.destroy(err => {
    if (err) {
      next(err);
    }
    res.redirect('/auth/login');
  });
});

router.get('/profile', isLoggedIn, (req, res) => {
  res.render('user/profile', { userInSession: req.session.currentUser });
});

module.exports = router;