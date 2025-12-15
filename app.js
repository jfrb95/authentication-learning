/////// app.js

const path = require("node:path");
const { Pool } = require("pg");
const express = require("express");
const session = require("express-session");
const passport = require("passport");
const LocalStrategy = require('passport-local').Strategy;

const pool = new Pool({
  host: "localhost",
  user: "jb",
  database: "authentication",
  password: "niceguy",
  port: "5432"
});

const app = express();
app.set("views", path.join(__dirname, "views"));
app.set("view engine", "ejs");

app.use(session({ secret: "cats", resave: false, saveUninitialized: false }));
app.use(passport.session());
app.use(express.urlencoded({ extended: false }));

//express allows us to store local variables to use throughout entire app,
//  even in views:
app.use((req, res, next) => {
  res.locals.currentUser = req.user;
  next();
});


app.get("/", (req, res) => {
  //if a user is logged in, i.e. there is a 'session', passport will
  //  have attached .user to req, due to what we put in passport.deserializeUser
  //  further down
  res.render("index", { user: req.user })
});


//ROUTES

app.get("/sign-up", (req, res) => res.render("sign-up-form"));
app.post("/sign-up", async (req, res, next) => {
  try {
    await pool.query("INSERT INTO users (username, password) VALUES ($1, $2)", [
      req.body.username,
      req.body.password,
    ]);
    res.redirect("/");
  } catch (err) {
    return next(err);
  }
});
app.post(
  "/log-in",
  passport.authenticate("local", {
    successRedirect: "/",
    failureRedirect: "/"
  })
);
app.get("/log-out", (req, res, next) => {
  //passport has a built-in log-out feature added to the req object
  req.logout((err) => {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});



//passport functions:

passport.use(
  //this function wll be called when passport.authentication() is used
  new LocalStrategy(async (username, password, done) => {
    try {
      const { rows } = await pool.query("SELECT * FROM users WHERE username = $1", [username]);
      const user = rows[0];

      if (!user) {
        return done(null, false, { message: "Incorrect username" });
      }
      if (user.password !== password) {
        return done(null, false, { message: "Incorrect password" });
      }
      return done(null, user);
    } catch (err) {
      return done(err);
    }
  })
);

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const { rows } = await pool.query("SELECT * FROM users WHERE id = $1", [id]);
    const user = rows[0];

    done(null, user);
  } catch (err) {
    done(err);
  }
});




app.listen(3000, (error) => {
  if (error) {
    throw error;
  }
  console.log("app listening on port 3000!");
});
