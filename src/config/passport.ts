import passport from 'passport'
import passportJwt from 'passport-jwt'
import passportFacebook from 'passport-facebook'
import passportGoogle from 'passport-google-oauth20'
import jwt from 'jsonwebtoken'
import _ from 'lodash'

// import { User, UserType } from '../models/User';
import { User, UserDocument } from '../models/user.model'
import { Request, Response, NextFunction } from 'express'
import { JWT_SECRET } from '../util/secrets'

passport.serializeUser<any, any>((user, done) => {
    done(undefined, user.id)
})

passport.deserializeUser((id, done) => {
    User.findById(id, (err, user) => {
        done(err, user)
    })
})

/**
 * Sign in using Email and Password.
 */
passport.use(new passportJwt.Strategy({
    jwtFromRequest: passportJwt.ExtractJwt.fromAuthHeaderAsBearerToken(),
    secretOrKey: process.env.JWT_SECRET
}, function (jwtPayload, done) {
    User.findOne({ id: jwtPayload.sub }, function (err, user) {
        if (err) {
            return done(err, false)
        }
        if (user) {
            return done(null, user)
        } else {
            return done(null, false)
            // or you could create a new account
        }
    })
}))

/**
 * OAuth Strategy Overview
 *
 * - User is already logged in.
 *   - Check if there is an existing account with a provider id.
 *     - If there is, return an error message. (Account merging not supported)
 *     - Else link new OAuth account with currently logged-in user.
 * - User is not logged in.
 *   - Check if it's a returning user.
 *     - If returning user, sign in and we are done.
 *     - Else check if there is an existing account with user's email.
 *       - If there is, return an error message.
 *       - Else create a new account.
 */


/**
 * Sign in with Facebook.
 */
passport.use(new passportFacebook.Strategy({
    clientID: process.env.FACEBOOK_ID,
    clientSecret: process.env.FACEBOOK_SECRET,
    callbackURL: '/auth/facebook/callback',
    profileFields: ['name', 'email', 'link', 'locale', 'timezone'],
    passReqToCallback: true
}, (req: any, accessToken, refreshToken, profile, done) => {
    if (req.user) {
        User.findOne({ facebook: profile.id }, (err, existingUser) => {
            if (err) { return done(err) }
            if (existingUser) {
                done(err)
            } else {
                User.findById(req.user.id, (err, user: any) => {
                    if (err) { return done(err) }
                    user.facebook = profile.id
                    user.tokens.push({ kind: 'facebook', accessToken })
                    user.profile.name = user.profile.name || `${profile.name.givenName} ${profile.name.familyName}`
                    user.profile.gender = user.profile.gender || profile._json.gender
                    user.profile.picture = user.profile.picture || `https://graph.facebook.com/${profile.id}/picture?type=large`
                    user.save((err: Error) => {
                        done(err, user)
                    })
                })
            }
        })
    } else {
        User.findOne({ facebook: profile.id }, (err, existingUser) => {
            if (err) { return done(err) }
            if (existingUser) {
                return done(undefined, existingUser)
            }
            User.findOne({ email: profile._json.email }, (err, existingEmailUser) => {
                if (err) { return done(err) }
                if (existingEmailUser) {
                    req.flash('errors', { msg: 'There is already an account using this email address. Sign in to that account and link it with Facebook manually from Account Settings.' })
                    done(err)
                } else {
                    const user: any = new User()
                    user.email = profile._json.email
                    user.facebook = profile.id
                    user.tokens.push({ kind: 'facebook', accessToken })
                    user.profile.name = `${profile.name.givenName} ${profile.name.familyName}`
                    user.profile.gender = profile._json.gender
                    user.profile.picture = `https://graph.facebook.com/${profile.id}/picture?type=large`
                    user.profile.location = (profile._json.location) ? profile._json.location.name : ''
                    user.save((err: Error) => {
                        done(err, user)
                    })
                }
            })
        })
    }
}))


passport.use(new passportGoogle.Strategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: '/auth/google/callback',
    passReqToCallback: true
}, (req: any, accessToken, refreshToken, profile, done) => {
    if (req.user) {
        User.findOne({ google: profile.id }, (err, existingUser) => {
            if (err) { return done(err) }
            if (existingUser) {
                done(err)
            } else {
                User.findById(req.user.id, (err, user: any) => {
                    if (err) { return done(err) }
                    user.google = profile.id
                    user.tokens.push({ kind: 'google', accessToken })
                    user.profile.name = user.profile.name || `${profile.name.givenName} ${profile.name.familyName}`
                    user.profile.picture = user.profile.picture
                    if (profile.photos && profile.photos.length > 0)
                        user.profile.picture = profile.photos[0].value
                    user.save((err: Error) => {
                        done(err, user)
                    })
                })
            }
        })
    } else {
        User.findOne({ google: profile.id }, (err, existingUser) => {
            if (err) { return done(err) }
            if (existingUser) {
                return done(undefined, existingUser)
            }
            User.findOne({ email: profile._json.email }, (err, existingEmailUser) => {
                if (err) { return done(err) }
                if (existingEmailUser) {
                    req.flash('errors', { msg: 'There is already an account using this email address. Sign in to that account and link it with Facebook manually from Account Settings.' })
                    done(err)
                } else {
                    const user: any = new User()
                    user.email = profile._json.email
                    user.google = profile.id
                    user.tokens.push({ kind: 'google', accessToken })
                    user.profile.name = `${profile.name.givenName} ${profile.name.familyName}`
                    user.profile.picture = ''
                    user.profile.location = (profile._json.location) ? profile._json.location.name : ''
                    user.save((err: Error) => {
                        done(err, user)
                    })
                }
            })
        })
    }
}))


/**
 * Login Required middleware.
 */
export const isAuthenticated = (req: Request, res: Response, next: NextFunction) => {
    try {
        const fullToken: string = req.headers.authorization.toString()

        const token = fullToken.split(" ")[1]
        jwt.verify(token, JWT_SECRET, function (err: any, payload: any) {
            if (payload) {
                User.findById(payload.userId).then(
                    (doc) => {
                        req.user = doc
                        next()
                    }
                )
            } else {
                res.status(401).json({ message: 'Not authenticated' })
            }
        })
    } catch (e) {
        res.status(401).json({ message: 'Not authenticated' })
    }
}

/**
 * Authorization Required middleware.
 */
export const isAuthorized = (req: Request, res: Response, next: NextFunction) => {
    const provider = req.path.split('/').slice(-1)[0]

    const user = req.user as UserDocument
    if (_.find(user.tokens, { kind: provider })) {
        next()
    } else {
        res.status(403).json({ message: 'Not Authorized' })
    }
}
