import dotenv from 'dotenv'

dotenv.config()

const getEnv = (key: string, required = true): string => {
  const value = process.env[key]
  if (!value && required) {
    throw new Error(`Environment variable ${key} is required but not set.`)
  }

  return value as string
}

const nodeEnv = getEnv('NODE_ENV', false) || 'development'
const docsEnabled =
  getEnv('DOCS_ENABLED', false) ?? (nodeEnv === 'production' ? 'false' : 'true')

const env = {
  port: parseInt(getEnv('PORT', false) || '3000', 10),
  nodeEnv,
  databaseUrl: getEnv('DATABASE_URL'),
  cookieSecret: getEnv('COOKIE_SECRET'),
  jwtSecret: getEnv('JWT_SECRET'),
  docsEnabled: docsEnabled === 'true',
  frontendUrl: getEnv('FRONTEND_URL', false) || 'http://localhost:5173',
  smtpHost: getEnv('SMTP_HOST', false),
  smtpPort: parseInt(getEnv('SMTP_PORT', false) || '587', 10),
  smtpSecure: (getEnv('SMTP_SECURE', false) || 'false') === 'true',
  smtpUser: getEnv('SMTP_USER', false),
  smtpPassword: getEnv('SMTP_PASSWORD', false),
  emailFrom:
    getEnv('EMAIL_FROM', false) || 'School Finder AI <no-reply@example.com>',
}

export default env
