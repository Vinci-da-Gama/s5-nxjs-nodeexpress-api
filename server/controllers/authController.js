const mongoose = require("mongoose");
const User = mongoose.model("User");
const passport = require("passport");
const { body, check } = require("express-validator");

exports.validateSignup = (req, res, next) => {
  body("name"); // sanitize inputed data, in case, there is sth wrong within
  body("email");
  body("password");

  // Name is non-null and is 4 to 10 characters
  check("name")
    .notEmpty()
    .withMessage("Enter a name")
    .isLength({ min: 4, max: 10 })
    .withMessage("Name must be between 4 and 10 characters");

  // Email is non-null, valid, and normalized
  check("email").isEmail().normalizeEmail().withMessage("Enter a valid email");

  // Password must be non-null, between 4 and 10 characters
  check("email")
    .notEmpty()
    .withMessage("Enter a password")
    .isLength({ min: 4, max: 10 })
    .withMessage("Password must be between 4 and 10 characters");

  const errors = req.validationErrors();
  if (errors) {
    const firstError = errors.map((error) => error.msg)[0];
    return res.status(400).send(firstError);
  }
  next();
};

exports.signup = async (req, res) => {
  const { name, email, password } = req.body;
  const user = await new User({ name, email, password });
  await User.register(user, password, (err, user) => {
    if (err) {
      return res.status(500).send(err.message);
    }
    res.json(user.name);
  });
};

exports.signin = (req, res, next) => {
  passport.authenticate("local", (err, user, info) => {
    if (err) {
      return res.status(500).json(err.message);
    }
    if (!user) {
      return res.status(400).json(info.message);
    }

    req.logIn(user, (err) => {
      if (err) {
        return res.status(500).json(err.message);
      }

      res.json(user);
    });
  })(req, res, next);
};

exports.signout = (req, res) => {
  res.clearCookie("next-cookie.sid");
  req.logout();
  res.json({ message: "You are now signed out!" });
};

exports.checkAuth = (req, res, next) => {
  if (req.isAuthenticated()) {
    return next();
  }
  res.redirect("/signin");
};
