export interface ClientInfo {
  ipAddress: string | null
  userAgent: string | null
}

export interface LoginT extends ClientInfo {
  email: string
  password: string
}

export type RefreshT = ClientInfo & {
  refreshToken: string
}

export type AuthSessionDbData = {
  user_id: string
  refreshTokenHash: string
  tokenFamily: string
  userAgent: string | null
  ipAddress: string | null
  expiresAt: Date
}

export type RotateRefreshTokenData = {
  authSessionId: string
  lastUsedAt: Date
  hashedRefreshToken: string
}

export type AccesTokenT = {
  sub: string
  session_Id: string
  role: string
  token_version: number
  refreshToken:string
}


