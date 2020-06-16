import { Router, Request, Response } from 'express'

// API keys and Passport configuration
import * as passportConfig from '../../config/passport'

import exampleController from './example.controller'
import restrictedController from './restricted.controller'

const router: Router = Router()

// Public routes
router.use('', exampleController)

// Restricted routes
router.use('/restricted', passportConfig.isAuthenticated, restrictedController)

router.use('**', (req: Request, res: Response) => {
    res.status(404).json({
        errors: ['Api endpoint does not exist']
    })
})

export default router