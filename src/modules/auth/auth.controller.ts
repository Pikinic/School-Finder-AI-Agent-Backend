import type { NextFunction, Request, Response } from 'express'
import { successResponse } from '../../http/response'
import { clearCookie, setCookie } from '../../http/cookie'
import AuthService from './auth.service'
import type { LoginT, RefreshT } from './auth.types'

const getRefreshTokenFromRequest = (req: Request): string => {
  return (req.body as { refreshToken: string }).refreshToken
}

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
  static Logout = async (req: Request, res: Response, next: NextFunction) => {
    try {
      if (!req.auth) {
        throw new Error('Authenticated request missing auth claims')
      }

      await AuthService.Logout({
        ...req.auth,
        refreshToken: getRefreshTokenFromRequest(req),
      })
      clearCookie(res)
      res.status(200).send(
        successResponse(true, 'Successfully logged out', undefined, {
          requestId: req.id,
        }),
      )
    } catch (error) {
      next(error)
    }
  }

  static LogoutAll = async (
    req: Request,
    res: Response,
    next: NextFunction,
  ) => {
    try {
      if (!req.auth) {
        throw new Error('Authenticated request missing auth claims')
      }

      await AuthService.LogoutAll({
        ...req.auth,
        refreshToken: getRefreshTokenFromRequest(req),
      })
      clearCookie(res)
      res.status(200).send(
        successResponse(true, 'All sessions logged out', undefined, {
          requestId: req.id,
        }),
      )
    } catch (error) {
      next(error)
    }
  }

  static UserDetails = async (
    req: Request,
    res: Response,
    next: NextFunction,
  ) => {
    try {
      if (!req.auth) {
        throw new Error('Authenticated request missing auth claims')
      }

      const getUserDetails = await AuthService.UserDetails(req.auth)
      res
        .status(200)
        .send(
          successResponse(
            true,
            'User details retrieved successfully',
            getUserDetails,
            { requestId: req.id },
          ),
        )
    } catch (error) {
      next(error)
    }
  }
}

export default AuthController
