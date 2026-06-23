interface ClientInfo {
  ipAddress: string | null
  userAgent: string | null
}

interface LoginT extends ClientInfo {
  email: string
  password: string
}

type RefreshT = ClientInfo & {
  refreshToken: string
}

type AuthSessionDbData = {
  user_id: string
  refreshTokenHash: string
  tokenFamily: string
  userAgent: string | null
  ipAddress: string | null
  expiresAt: Date
}

type RotateRefreshTokenData = {
  authSessionId: string
  lastUsedAt: Date
  hashedRefreshToken: string
}

export { LoginT, RefreshT, AuthSessionDbData, RotateRefreshTokenData }
