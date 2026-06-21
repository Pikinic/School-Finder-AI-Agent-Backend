import type { NextFunction, Request, Response } from 'express'
import env from '../../config/env'
import { successResponse } from '../../http/response'
import AuthService from './auth.service'
import type { LoginT } from './auth.types'

class AuthController {
  static Login = async (req: Request, res: Response, next: NextFunction) => {
    try {
      const userAgent = req.headers['user-agent'] ?? null
      const ipAddress = req.ip ?? null
      const loginUser = await AuthService.Login(
        req.body as LoginT,
        userAgent,
        ipAddress,
      )

      res.cookie('refreshToken', loginUser.refreshToken, {
        httpOnly: true,
        secure: env.nodeEnv === 'production',
        sameSite: 'strict',
        maxAge: 1000 * 60 * 60 * 24 * 30,
      })

      res.status(200).send(
        successResponse(true, 'Login successful', loginUser.data, {
          requestId: req.id,
        }),
      )
    } catch (err) {
      next(err)
    }
  }
}

export default AuthController
