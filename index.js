require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const ejs= require('ejs');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const saltRounds = 10;

var app = express();
app.set('view engine', 'ejs');
app.use(express.urlencoded({extended: true}));
app.use(express.static("public"));
app.use(cookieParser());
const PORT = process.env.PORT || 5000;

// const mongoUrl = process.env.MONGO_URL_LOCAL // Uncomment this line if you want to use a local MongoDB instance
const mongoUrl = process.env.MONGO_URL;
mongoose.connect(mongoUrl, {
    dbName: "secretsDB" // Optional: specify your DB name
}).then(() => {
    console.log("Connected to MongoDB Atlas");
}).catch((err) => {
    console.error("MongoDB connection error:", err);
});

const userSchema = new mongoose.Schema({
    name: String,
    email: String,
    password: String,
    secrets: [String], // Change from 'secret: String' to 'secrets: [String]'
  
});
const User = mongoose.model("User", userSchema);

const JWT_SECRET = process.env.JWT_SECRET;

app.get("/", function(req, res){
    res.render("home");
});
// app.js registration route
app.post("/register", async function(req, res){
    const { name, username, password } = req.body;
    if (!validateEmail(username)) {
        return res.send("Invalid email format.");
    }
    if (!isValidPassword(password)) {
        return res.send("Password must be 6-8 characters, include uppercase, lowercase, a number, and a special character.");
    }
    try {
        const hash = await bcrypt.hash(password, saltRounds);
        const newUser = new User({
            name: name,
            email: username,
            password: hash
        });
        await newUser.save();
        res.redirect("/login");
    } catch (err) {
        console.log(err);
        res.redirect("/register");
    }
});
app.post("/login", async function(req, res){
    const { username, password } = req.body;
    if (!validateEmail(username)) {
        return res.send("Invalid email format.");
    }
    try {
        const foundUser = await User.findOne({email: username});
        if (foundUser && await bcrypt.compare(password, foundUser.password)) {
            const token = jwt.sign(
                { id: foundUser._id, email: foundUser.email },
                JWT_SECRET,
                { expiresIn: '1h' }
            );
            res.cookie('token', token, { httpOnly: true, secure: false }); // set secure: true in production
            res.redirect("/secrets");
        } else {
            res.send("Incorrect email or password");
        }
    } catch (err) {
        console.log(err);
        res.redirect("/login");
    }
});
app.get("/login", function(req, res){
    res.render("login");
});
app.get("/register", function(req, res){
    res.render("register");
});
app.get("/logout", function(req, res){
    res.clearCookie('token');
    res.redirect("/login");
});
app.get("/submit", authenticateToken, function(req, res){
    res.render("submit");
});

app.post("/submit", authenticateToken, async function(req, res){
    const submittedSecret = req.body.secret;
    try {
        await User.findByIdAndUpdate(
            req.user.id,
            { $push: { secrets: submittedSecret } }
        );
        res.redirect("/secrets");
    } catch (err) {
        console.log(err);
        res.redirect("/submit");
    }
});
app.post("/delete-secret", authenticateToken, async function(req, res){
    const secretToDelete = req.body.secret;
    try {
        await User.findByIdAndUpdate(
            req.user.id,
            { $pull: { secrets: secretToDelete } }
        );
        res.redirect("/secrets");
    } catch (err) {
        console.log(err);
        res.redirect("/secrets");
    }
});

function validateEmail(email) {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}
 function isValidPassword(password) {
        return /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z\d]).{6,8}$/.test(password);
    }


function authenticateToken(req, res, next) {
    const token = req.cookies.token;
    if (!token) return res.redirect("/login");
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.redirect("/login");
        req.user = user;
        next();
    });
}

// Protect secrets route
app.get("/secrets", authenticateToken, async function(req, res){
    const user = await User.findById(req.user.id);
    res.render("secrets", { user });
});

app.get("/profile", authenticateToken, async function(req, res){
    const user = await User.findById(req.user.id);
    res.render("profile", { user });
});


app.listen(5000, function(){
    console.log("Server started on port 5000");
});
