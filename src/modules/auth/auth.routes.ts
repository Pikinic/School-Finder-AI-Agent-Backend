import express, { type Router } from 'express'
import { validate, validateRefreshToken } from '../../middleware/validate'
import AuthController from './auth.controller'
import { loginSchema, refreshTokenSchema } from './auth.schemas'
import { clientInfo } from '../../middleware/clientInfo'
import { AuthenticateMiddleware } from '../../middleware/authenticate'

export const authRouter: Router = express.Router()

authRouter.post('/login', validate(loginSchema), clientInfo, AuthController.Login)
authRouter.post('/refresh', validateRefreshToken(refreshTokenSchema), clientInfo, AuthController.Refresh)
authRouter.post("/logout", AuthenticateMiddleware, validateRefreshToken(refreshTokenSchema),  AuthController.Logout)