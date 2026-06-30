import nodemailer from 'nodemailer'
import env from '../../config/env'
import { logger } from '../../config/logger'
import type { SendEmailData } from './email.types'

const createTransport = () => {
  if (!env.smtpHost) {
    return nodemailer.createTransport({ jsonTransport: true })
  }

  return nodemailer.createTransport({
    host: env.smtpHost,
    port: env.smtpPort,
    secure: env.smtpSecure,
    auth:
      env.smtpUser && env.smtpPassword
        ? {
            user: env.smtpUser,
            pass: env.smtpPassword,
          }
        : undefined,
  })
}

class EmailProvider {
  private static transporter = createTransport()

  static send = async (data: SendEmailData) => {
    const result = await EmailProvider.transporter.sendMail({
      from: env.emailFrom,
      to: data.to,
      subject: data.subject,
      html: data.html,
      text: data.text,
    })

    logger.info(
      {
        messageId: result.messageId,
        to: data.to,
        subject: data.subject,
        transport: env.smtpHost ? 'smtp' : 'json',
      },
      'Email sent',
    )
  }
}

export default EmailProvider
