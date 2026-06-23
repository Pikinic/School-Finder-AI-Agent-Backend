import crypto from 'node:crypto'
import { createError } from '../errors/AppError'

export const hashRefreshToken = (token: string) => {
  try {
    return crypto.createHash('sha256').update(token).digest('hex')
  } catch (err) {
    throw createError(
      'Error hashing refresh token',
      500,
      { stack: err instanceof Error ? err.stack : undefined },
      'REFRESH_TOKEN_HASH_ERROR',
    )
  }
}
