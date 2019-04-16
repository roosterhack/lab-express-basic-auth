const express = require("express");
const bcrypt = require("bcrypt");
const User = require("../models/user");
const router = express.Router();
const zxcvbn = require("zxcvbn");

//Render the signup page
router.get("/signup", (req, res, next) => {
  res.render("auth/signup");
});

// create login route
router.get("/login", (req, res, next) => {
  res.render("auth/login");
});

//Route to secret page
router.get("/secret", (req, res, next) => {
  if (req.session.loggedInUser) {
    res.render("auth/secret");
  } else {
    res.render("error");
  }
});

//Route to private page
router.get("/main", (req, res, next) => {
  if (req.session.loggedInUser) {
    res.render("auth/main");
  } else {
    res.render("error");
  }
});

//Logout
router.get("/logout", (req, res, next) => {
  req.session.destroy(() => {
    res.redirect("/");
    console.log("you are logged out");
  });
});

//create POST method for logging in
router.post("/login", (req, res, next) => {
  const { username, password } = req.body;
  if (!username || !password) {
    res.render("auth/login", {
      errorMessage: "You need to enter a username and a password"
    });
    return;
  }
  User.findOne({ username })
    .then(user => {
      if (!user) {
        res.render("auth/login", {
          errorMessage: "This username was not found"
        });
      }
      if (bcrypt.compareSync(password, user.password)) {
        req.session.loggedInUser = true;
        res.redirect("/secret");
      } else {
        res.render("auth/login", {
          errorMessage: "Wrong password mate!"
        });
      }
    })
    .catch(err => {
      console.error("Error finding user", err);
      next();
    });
});

//Sign up and create a user
router.post("/signup", (req, res, next) => {
  const { username, password } = req.body;
  const salt = bcrypt.genSaltSync();
  const hashPassword = bcrypt.hashSync(password, salt);

  //check if password and username are not empty
  if (username === "" || password === "") {
    res.render("auth/signup", {
      errorMessage: "You need to enter a username and a password"
    });
    return;
  }

  //Check password strength
  const passwordStrength = zxcvbn(password);
  if (password.length < 6) {
    res.render("auth/signup", {
      errorMessage: "Your password needs 6 or more characters"
    });
    return;
  }
  if (passwordStrength.score === 0) {
    res.render("auth/signup", {
      errorMessage: passwordStrength.feedback.warning
    });
    return;
  }

  //use user schema to create a user and ensure user is new
  User.findOne({ username })
    .then(user => {
      if (user) {
        res.render("auth/signup", {
          errorMessage: "There is already a user with this username"
        });
        return;
      }
      User.create({ username, password: hashPassword })
        .then(() => {
          res.redirect("/");
        })
        .catch(err => {
          console.error("Error while registering new user", err);
          next();
        });
    })
    .catch(err => {
      console.log(err);
      next();
    });
});

module.exports = router;
