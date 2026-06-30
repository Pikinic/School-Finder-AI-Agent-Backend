export type SendEmailData = {
  to: string
  subject: string
  html: string
  text: string
}

export type PasswordResetEmailData = {
  to: string
  fullName: string
  resetUrl: string
  expiresInMinutes: number
}
