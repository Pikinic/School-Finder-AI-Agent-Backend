import type { NextFunction, Request, Response } from 'express'
import { successResponse } from '../../http/response'
import { setCookie } from '../../http/cookie'
import AuthService from './auth.service'
import type { LoginT, RefreshT } from './auth.types'

class AuthController {
  static Login = async (req: Request, res: Response, next: NextFunction) => {
    try {
      const loginUser = await AuthService.Login(req.body as LoginT)

      setCookie(res, loginUser.refreshToken)
      res.status(200).send(
        successResponse(true, 'Login successful', loginUser.data, {
          requestId: req.id,
        }),
      )
    } catch (err) {
      next(err)
    }
  }

  static Refresh = async (req: Request, res: Response, next: NextFunction) => {
    try {
      const refreshToken = await AuthService.Refresh(req.body as RefreshT)
      setCookie(res, refreshToken.newRefreshToken)
      res
        .status(200)
        .send(
          successResponse(
            true,
            'Refresh successful',
            { accessToken: refreshToken.accessToken },
            { requestId: req.id },
          ),
        )
    } catch (error) {
      next(error)
    }
  }
}

export default AuthController
