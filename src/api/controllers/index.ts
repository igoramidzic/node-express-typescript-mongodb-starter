import { Router, Request, Response } from "express"

// API keys and Passport configuration
import * as passportConfig from "../../config/passport"

const router: Router = Router()

// Public routes
router.use('', require('./example.controller'))

// Restricted routes
router.use('/restricted', passportConfig.isAuthenticated, require('./restricted.controller'))

router.use('**', (req: Request, res: Response) => {
    res.status(404).json({
        errors: ['Api endpoint does not exist']
    })
})

module.exports = router