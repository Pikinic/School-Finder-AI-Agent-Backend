import crypto from 'node:crypto'
import { createError } from '../errors/AppError'

export const generateOpaqueToken = (): string => {
  return crypto.randomBytes(64).toString('hex')
}

export const hashOpaqueToken = (token: string): string => {
  try {
    return crypto.createHash('sha256').update(token).digest('hex')
  } catch (err) {
    throw createError(
      'Error hashing token',
      500,
      { stack: err instanceof Error ? err.stack : undefined },
      'TOKEN_HASH_ERROR',
    )
  }
}
