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

// Controllers (route handlers)
import * as apiController from "./controllers/api"

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

/**
 * API examples routes.
 */
app.get("/api", apiController.getApi)

export default app
