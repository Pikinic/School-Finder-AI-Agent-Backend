import type { NextFunction, Request, Response } from 'express'
import { createError } from '../common/errors/AppError'
import { AUTH_ERROR_CODES } from '../common/errors/errorCodes'
import { decodeAcessToken } from '../common/security/token'
import type { AccessTokenClaims } from '../modules/auth/auth.types'

export const AuthenticateMiddleware = (
  req: Request,
  _res: Response,
  next: NextFunction,
) => {
  try {
    const [scheme, accessToken] = req.headers.authorization?.split(' ') ?? []

    if (scheme !== 'Bearer' || !accessToken) {
      return next(
        createError('Not authorized', 401, {}, AUTH_ERROR_CODES.TOKEN_MISSING),
      )
    }

    req.auth = decodeAcessToken(accessToken) as AccessTokenClaims
    next()
  } catch (error) {
    next(error)
  }
}
