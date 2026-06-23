import { randomUUID } from 'node:crypto'
import { AUTH_ERROR_CODES } from '../../common/errors/errorCodes'
import { createError } from '../../common/errors/AppError'
import { verifyPassword } from '../../common/security/password'
import {
  generateAcessToken,
  generateRefreshToken,
} from '../../common/security/token'
import { hashRefreshToken} from '../../common/security/tokenHash'
import AuthRepo from './auth.repository'
import type { AuthSessionDbData, LoginT } from './auth.types'

class AuthService {
  static Login = async (
    requestBody:LoginT
  ) => {
    const user = await AuthRepo.findUser({email: requestBody.email})

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
    const refreshTokenHash = await hashRefreshToken(refreshToken)
    const tokenFamily = randomUUID()
    const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000)

    const createAuthSessionData: AuthSessionDbData = {
      user_id: user.id,
      refreshTokenHash,
      tokenFamily,
      userAgent:requestBody.userAgent,
      ipAddress: requestBody.ipAddress,
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

    return { data, refreshToken}
  }

  static Refresh = async (data:{refreshToken:string, ipAddress:string, userAgent:string})=>{
    const hashedRefreshToken  =  await hashRefreshToken(data.refreshToken) //we hash incoming refresh Token
     const authSession = await AuthRepo.findAuthSession(hashedRefreshToken) // Find auth session
     if(!authSession?.refresh_token_hash){
        throw createError(
        'Authentication session not found or has expired',
        401,
        {},
        AUTH_ERROR_CODES.AUTH_SESSION_NOT_FOUND,
      )
     }
    
     const authExpiryDate = new Date(authSession.expires_at)
     if(authExpiryDate <= new Date()){
           throw createError(
        'Authentication session has expired, please log in again',
        401,
        {},
        'AUTH_SESSION_EXPIRED',
      )
     }

    if(authSession.revoked_at){
       throw createError(
        'Authentication session revoked, please log in again',
        401,
        {},
        'AUTH_SESSION_REVOKED',
      )
    }

    const user = await AuthRepo.findUser({id:authSession.user_id})
    if(user?.status !=  "ACTIVE"){
        throw createError(
        'Account is not active',
        403,
        {},
        AUTH_ERROR_CODES.ACCOUNT_DISABLED,
      )
    }

    if(authSession.ip_address != data.ipAddress && authSession.user_agent != data.userAgent){
       throw createError(
        'Session device mismatch detected. Please log in again.',
        401,
        {},
       'AUTH_SESSION_DEVICE_MISMATCH',
      )
    }
    
   
  const accessToken = generateAcessToken(user.id, authSession.id, user.role, user.token_version)
  const newRefreshToken =  generateRefreshToken()
  const newHashedRefreshToken = await hashRefreshToken(newRefreshToken)

  const updateRefreshToken =  AuthRepo.updateRefreshToken({auth_id:authSession.id, hashedRefreshToken:newHashedRefreshToken})
  return {newRefreshToken, accessToken}
  
}



}

export default AuthService
