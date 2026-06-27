import type { AccessTokenClaims } from '../modules/auth/auth.types'

declare global {
  namespace Express {
    interface Request {
      id: string
      auth?: AccessTokenClaims
    }
  }
}

export {}
