import express, { type Router } from 'express'
import { validate } from '../../middleware/validate'
import AuthController from './auth.controller'
import { loginSchema } from './auth.schemas'

export const authRouter: Router = express.Router()

authRouter.post('/login', validate(loginSchema), AuthController.Login)
