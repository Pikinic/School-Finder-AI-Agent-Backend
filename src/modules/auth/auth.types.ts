type LoginT = {
  email: string
  password: string
}

type AuthSessionDbData = {
  user_id: string
  refreshTokenHash: string
  tokenFamily: string
  userAgent: string | null
  ipAddress: string | null
  expiresAt: Date
}
export { LoginT, AuthSessionDbData }
