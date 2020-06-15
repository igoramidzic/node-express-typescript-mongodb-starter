import express from "express"
import session from "express-session"
import bodyParser from "body-parser"
import mongo from "connect-mongo"
import flash from "express-flash"
import mongoose from "mongoose"
import passport from "passport"
import bluebird from "bluebird"
import { MONGODB_URI, SESSION_SECRET } from "./util/secrets"

const MongoStore = mongo(session)

// Create Express server
const app = express()

// Connect to MongoDB
const mongoUrl = MONGODB_URI
mongoose.Promise = bluebird

mongoose.connect(mongoUrl, { useNewUrlParser: true, useCreateIndex: true, useUnifiedTopology: true }).then(
    () => { /** ready to use. The `mongoose.connect()` promise resolves to undefined. */ },
).catch(err => {
    console.log("MongoDB connection error. Please make sure MongoDB is running. " + err)
    // process.exit();
})

// Express configuration
app.set("port", process.env.PORT || 3000)
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: true }))
app.use(session({
    resave: true,
    saveUninitialized: true,
    secret: SESSION_SECRET,
    store: new MongoStore({
        url: mongoUrl,
        autoReconnect: true
    })
}))
app.use(passport.initialize())
app.use(passport.session())
app.use(flash())
app.use((req, res, next) => {
    res.locals.user = req.user
    next()
})

// API keys and Passport configuration
import * as passportConfig from "./config/passport"

/**
 * API examples routes.
 */
app.use("/api", require('./api/controllers/index'))

/**
 * OAuth authentication routes. (Sign in)
 */
app.get("/auth/facebook", passport.authenticate("facebook", { scope: ["email", "public_profile"] }, (res) => {
    console.log(res)
}))
app.get("/auth/facebook/callback", passport.authenticate("facebook"), (req, res) => {
    res.status(200).json(req.user)
})

app.get("/auth/logout", passportConfig.isAuthenticated, (req, res) => {
    req.logOut()
    res.status(200).json({ message: 'Successful logout' })
})

export default app
