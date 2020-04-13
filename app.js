const express = require('express');
const session = require('express-session');
const path = require('path');
const mongoose = require('mongoose');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcryptjs');
const Schema = mongoose.Schema;
const dotenv = require('dotenv').config();

const mongoDb = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0-gevd4.azure.mongodb.net/userAuthentication?retryWrites=true&w=majority`;
mongoose.connect(mongoDb, {useUnifiedTopology: true, useNewUrlParser: true});
const db = mongoose.connection;
db.on("error", console.error.bind(console, "mongo connection error"));


const User = mongoose.model(
    "User",
    {
        username: {type: String, required: true},
        password: {type: String, required: true}
    }
)

const app = express();
app.set("views", __dirname);
app.set("view engine", "ejs");

// set up LocalStrategy for username / password authentication
// takes our username and password and runs it against values in our database + make sure user's password matches username
passport.use(
    new LocalStrategy((username, password, done) => {
        User.findOne({username: username}, (err, user) => {
            if(err) {
                return done(err);
            }
            if(!user) {
                return done(null, false, {msg: 'Incorrect username'});
            }
            // use bcrypt to compare serialized password with regular password
            bcrypt.compare(password, user.password,(err, res) => {
                if(res) {
                    return done(null, user);
                } else {
                    return done(null, false, {msg: 'Incorrect password'});
                }
            })
            return done(null, user);
        })
    })
)

// creates a cookie and stores it in the browser 
// creates and decodes the cookie

// sets the id to user's cookie / saved in the session
// sets the object as req.session.passport.user = {}
passport.serializeUser(function(user, done) {
    done(null, user.id);
})

// retrieves the user.id throughout the site through an object
// retrieves the object above
passport.deserializeUser(function(id, done) {
    User.findById(id, function(err, user) {
        done(err, user);
    })
})

app.use(session({secret: "cats", resave: false, saveUninitialized: true}))
app.use(passport.initialize());
app.use(passport.session());
app.use(express.urlencoded({extended: false}))

var router = express.Router();

// set and access various local variables throughout your entire app
router.use(function(req, res, next) {
    res.locals.currentUser = req.user;
    next();
})

app.get('/', (req, res) => {
    // check for req.user to see if user is logged in
    res.render('index', {user: req.user});
})

app.get('/sign-up', (req, res) => {
    res.render('sign-up-form');
})

app.post("/sign-up", (req, res, next) => {
    bcrypt.hash(req.body.password, 10, (err, hashedPassword) => {
        if(err) {
            return next(err);
        } else {
            const user = new User(
                {
                    username: req.body.username,
                    password: hashedPassword
                }
            ).save((err) => {
                if(err) {
                    return next(err);
                } else {
                    res.redirect('/');
                }
            })
        }
    })
})

// set up post route for /log-in
// looks for request body for parameters (username, password) then runs LocalStrategy in the background
// --> creates a session cookie that we can access in all future requests
app.post(
    '/log-in', 
    passport.authenticate("local", 
    {
        successRedirect: '/',
        failureRedirect: '/'
    }
    )
)

app.get('/log-out', (req, res) => {
    req.logout();
    res.redirect('/');
})

app.listen(3000, () => {
    console.log('app is listening at port 3000');
})