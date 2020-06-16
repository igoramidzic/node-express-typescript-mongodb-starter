import express, { Request, Response } from 'express'
import bodyParser from 'body-parser'
import flash from 'express-flash'
import mongoose from 'mongoose'
import bluebird from 'bluebird'
import passport from 'passport'
import jwt from 'jsonwebtoken'
import { MONGODB_URI, JWT_SECRET } from './util/secrets'

import apiControllers from './api/controllers/index'

// Create Express server
const app = express()

// Connect to MongoDB
const mongoUrl = MONGODB_URI
mongoose.Promise = bluebird

mongoose.connect(mongoUrl, { useNewUrlParser: true, useCreateIndex: true, useUnifiedTopology: true }).then(
    () => { /** ready to use. The `mongoose.connect()` promise resolves to undefined. */ },
).catch(err => {
    console.log('MongoDB connection error. Please make sure MongoDB is running. ' + err)
    // process.exit();
})

// Express configuration
app.set('port', process.env.PORT || 3000)
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: true }))
app.use(flash())
app.use(passport.initialize())
app.use((req, res, next) => {
    res.locals.user = req.user
    next()
})

/**
 * API examples routes.
 */
app.use('/api', apiControllers)

/**
 * OAuth authentication routes. (Sign in)
 */
app.get('/auth/facebook', passport.authenticate('facebook', { scope: ['email', 'public_profile'] }))
app.get('/auth/facebook/callback', passport.authenticate('facebook', { failureRedirect: '/login' }), (req, res) => {
    const user: any = req.user
    if (!user)
        return res.status(401).json({ message: 'Authentication failed' })

    const token = jwt.sign({ userId: user.id }, JWT_SECRET)
    res.status(200).json({ user: req.user, token })
})

app.get('/auth/google', passport.authenticate('google', { scope: ['profile'] }))
app.get('/auth/google/callback', passport.authenticate('google', {}), (req, res) => {
    const user: any = req.user
    if (!user)
        return res.status(401).json({ message: 'Authentication failed' })

    const token = jwt.sign({ userId: user.id }, JWT_SECRET)
    res.status(200).json({ user: req.user, token })
})

export default app
