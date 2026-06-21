import { randomUUID } from 'node:crypto'
import { AUTH_ERROR_CODES } from '../../common/errors/errorCodes'
import { createError } from '../../common/errors/AppError'
import { verifyPassword } from '../../common/security/password'
import {
  generateAcessToken,
  generateRefreshToken,
} from '../../common/security/token'
import { hashRefreshToken } from '../../common/security/tokenHash'
import AuthRepo from './auth.repository'
import type { AuthSessionDbData, LoginT } from './auth.types'

class AuthService {
  static Login = async (
    requestBody: LoginT,
    userAgent: string | null,
    ipAddress: string | null,
  ) => {
    const user = await AuthRepo.findUser(requestBody.email)

    if (!user?.password_hash) {
      throw createError(
        'Invalid email or password',
        401,
        {},
        AUTH_ERROR_CODES.INVALID_CREDENTIALS,
      )
    }

    if (user.status !== 'ACTIVE') {
      throw createError(
        'Account is not active',
        403,
        {},
        AUTH_ERROR_CODES.ACCOUNT_DISABLED,
      )
    }

    const passwordMatches = await verifyPassword(
      user.password_hash,
      requestBody.password,
    )

    if (!passwordMatches) {
      throw createError(
        'Invalid email or password',
        401,
        {},
        AUTH_ERROR_CODES.INVALID_CREDENTIALS,
      )
    }

    const refreshToken = generateRefreshToken()
    const refreshTokenHash = hashRefreshToken(refreshToken)
    const tokenFamily = randomUUID()
    const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000)

    const createAuthSessionData: AuthSessionDbData = {
      user_id: user.id,
      refreshTokenHash,
      tokenFamily,
      userAgent,
      ipAddress,
      expiresAt,
    }

    const authSession = await AuthRepo.createAuthSession(createAuthSessionData)
    await AuthRepo.updateLastLogin(user.id)

    const accessToken = generateAcessToken(
      user.id,
      authSession.id,
      user.role,
      user.token_version,
    )

    const data = {
      accessToken,
      user: {
        publicId: user.public_id,
        fullName: user.full_name,
        email: user.email,
        role: user.role,
        status: user.status,
      },
    }

    return { data, refreshToken }
  }
}

export default AuthService
