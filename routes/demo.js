const express = require("express");
const bcrypt = require("bcryptjs");

const db = require("../data/database");

const router = express.Router();

router.get("/", function (req, res) {
  res.render("welcome");
});

router.get("/signup", function (req, res) {
  let sessionInputData = req.session.inputData;

  if (!sessionInputData){
    sessionInputData = {
      hasError: false,
      email: '',
      confirmEmail: '',
      password: '',
    }
  } 

  req.session.inputData = null;

  res.render("signup", {inputData: sessionInputData});
});

router.get("/login", function (req, res) {
  let sessionInputData = req.session.inputData;

  if (!sessionInputData){
    sessionInputData = {
      hasError: false,
      email: '',
      confirmEmail: '',
      password: '',
    }
  } 

  req.session.inputData = null;
  res.render("login", {inputData: sessionInputData});
});

router.post("/signup", async function (req, res) {
  const userData = req.body;

  const enteredEmail = userData.email;
  const enteredConfirmEmail = userData["confirm-email"];
  const enteredPassword = userData.password;

  if (
    !enteredEmail ||
    !enteredEmail.includes('@') ||
    !enteredConfirmEmail ||
    !enteredPassword ||
    enteredEmail !== enteredConfirmEmail ||
    enteredPassword.trim() < 6 
  ) {
    req.session.inputData = {
      hasError: true,
      message: "Invalid Input - please check your data!",
      email: enteredEmail,
      confirmEmail: enteredConfirmEmail,
      password: enteredPassword
    }

    req.session.save(function() {
      res.redirect("/signup");
    })
    return;
  }

  const existingUser = await db.getDb().collection('users').findOne({email: enteredEmail});

  if (existingUser) {
    req.session.inputData = {
      hasError: true,
      message: "User already exist!",
      email: enteredEmail,
      confirmEmail: enteredConfirmEmail,
      password: enteredPassword
    }
    req.session.save(function() {
      res.redirect('/signup');
    })
    return;
  }

  const hashedPassword = await bcrypt.hash(enteredPassword, 12);

  const user = {
    email: enteredEmail,
    password: hashedPassword,
  };

  await db.getDb().collection("users").insertOne(user);

  res.redirect("/login");
});

router.post("/login", async function (req, res) {
  const userData = req.body;

  const enteredEmail = userData.email;
  const enteredPassword = userData.password;

  const existingUser = await db
    .getDb()
    .collection("users")
    .findOne({ email: enteredEmail });

  if (!existingUser) {
    req.session.inputData = {
      hasError: true,
      message: "Could not log you in - Please check your credentials!",
      email: enteredEmail,
      password: enteredPassword
    }  
    req.session.save(function() {
      res.redirect("/login");
    })  
    return 
  }

  const passwordAreEqual = await bcrypt.compare(
    enteredPassword,
    existingUser.password
  );

  if (!passwordAreEqual) {
    req.session.inputData = {
      hasError: true,
      message: "Could not log you in - Please check your credentials!",
      email: enteredEmail,
      password: enteredPassword
    }      
    req.session.save(function() {
      res.redirect("/login");
    })  
    return
  }

  req.session.user = {id: existingUser._id, email: existingUser.email, isAdmin: existingUser.isAdmin};
  req.session.isAuthenticated = true;
  req.session.save(function() {
    res.redirect("/profile");
  })
});

router.get("/profile", function (req, res) {
  if (!res.locals.isAuth) {
    return res.status(401).render('401')
  }
  res.render("profile");
});

router.get("/admin", async function (req, res) {
  if (!res.locals.isAuth) {
    return res.status(401).render('401')
  }

  if (!res.locals.isAdmin) {
    return res.status(403).render('403');
  }

  res.render("admin");
});

router.post("/logout", function (req, res) {
  req.session.user = null;
  req.session.isAuthenticated = false;
  res.redirect('/')
});

module.exports = router;
