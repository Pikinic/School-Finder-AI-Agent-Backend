import { createError } from '../../common/errors/AppError'
import prisma from '../../database/prisma'
import type { AuthSessionDbData, RotateRefreshTokenData } from './auth.types'

class AuthRepo {
  static async findUser(where: { email?: string; id?: string }) {
    const user = await prisma.users.findFirst({
      where,
    })

    return user
  }

  static async createAuthSession(data: AuthSessionDbData) {
    try {
      const authSession = await prisma.auth_Sessions.create({
        data: {
          user_id: data.user_id,
          refresh_token_hash: data.refreshTokenHash,
          token_family: data.tokenFamily,
          user_agent: data.userAgent,
          ip_address: data.ipAddress,
          expires_at: data.expiresAt,
          revoked_at: null,
          last_used_at: null,
        },
        select: { id: true, expires_at: true },
      })

      return authSession
    } catch (err) {
      throw createError(
        'Failed to create auth session',
        500,
        { stack: err instanceof Error ? err.stack : undefined },
        'DATABASE_ERROR',
      )
    }
  }

  static async updateLastLogin(userId: string) {
    await prisma.users.update({
      where: { id: userId },
      data: { last_login_at: new Date() },
    })
  }
  static async findAuthSession(hashedRefreshToken: string) {
    const authSession = await prisma.auth_Sessions.findUnique({
      where: { refresh_token_hash: hashedRefreshToken },
    })

    return authSession
  }

  static async rotateRefreshToken(data: RotateRefreshTokenData) {
    return prisma.auth_Sessions.update({
      where: { id: data.authSessionId },
      data: {
        refresh_token_hash: data.hashedRefreshToken,
        last_used_at: data.lastUsedAt,
      },
    })
  }

  static async revokeAuthSession(sessionId: string) {
    await prisma.auth_Sessions.update({
      where: {
          id: sessionId,
        revoked_at: null,
      },
      data: { revoked_at: new Date() },
    })
  }

  static async revokeAuthSessionFamily(userId:string){
    await prisma.auth_Sessions.updateMany({
       where:{
        user_id:userId,
        revoked_at:null
       },
       data:{revoked_at: new Date()}
    })
  }
}

export default AuthRepo
