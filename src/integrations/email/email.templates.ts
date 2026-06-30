import type { PasswordResetEmailData, SendEmailData } from './email.types'

const escapeHtml = (value: string): string => {
  return value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;')
}

export const buildPasswordResetEmail = (
  data: PasswordResetEmailData,
): SendEmailData => {
  const fullName = escapeHtml(data.fullName)
  const resetUrl = escapeHtml(data.resetUrl)
  const expiresInMinutes = data.expiresInMinutes.toString()

  const text = [
    `Hi ${data.fullName},`,
    '',
    `Use this link to reset your School Finder AI password. It expires in ${expiresInMinutes} minutes:`,
    data.resetUrl,
    '',
    'If you did not request this, you can ignore this email.',
    '',
    'Pikinic School Finder AI',
  ].join('\n')

  const html = `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Reset your password</title>
  </head>
  <body style="margin:0;background:#F5F6F8;color:#111827;font-family:Arial,Helvetica,sans-serif;">
    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background:#F5F6F8;margin:0;padding:32px 16px;">
      <tr>
        <td align="center">
          <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="max-width:560px;background:#FFFFFF;border:1px solid #E5E7EB;border-radius:16px;overflow:hidden;">
            <tr>
              <td style="padding:28px 32px 20px;border-bottom:1px solid #E5E7EB;">
                <div style="font-size:14px;font-weight:700;color:#045A58;letter-spacing:0;">School Finder AI</div>
                <h1 style="margin:18px 0 0;font-size:24px;line-height:32px;color:#111827;font-weight:700;">Reset your password</h1>
              </td>
            </tr>
            <tr>
              <td style="padding:28px 32px 32px;">
                <p style="margin:0 0 16px;font-size:15px;line-height:24px;color:#111827;">Hi ${fullName},</p>
                <p style="margin:0 0 24px;font-size:15px;line-height:24px;color:#374151;">We received a request to reset your School Finder AI password. Use the secure link below to choose a new password.</p>
                <table role="presentation" cellspacing="0" cellpadding="0" style="margin:0 0 24px;">
                  <tr>
                    <td style="border-radius:10px;background:#045A58;">
                      <a href="${resetUrl}" style="display:inline-block;padding:12px 18px;color:#FFFFFF;text-decoration:none;font-size:14px;font-weight:700;border-radius:10px;">Reset password</a>
                    </td>
                  </tr>
                </table>
                <div style="margin:0 0 24px;padding:14px 16px;background:#E6F4F3;border:1px solid #BFE4E1;border-radius:12px;color:#034A48;font-size:14px;line-height:22px;">
                  This link expires in ${expiresInMinutes} minutes. If it expires, request a new reset link from the login page.
                </div>
                <p style="margin:0 0 10px;font-size:13px;line-height:21px;color:#6B7280;">If the button does not work, copy and paste this URL into your browser:</p>
                <p style="margin:0 0 24px;font-size:13px;line-height:20px;word-break:break-all;color:#045A58;">${resetUrl}</p>
                <p style="margin:0;font-size:13px;line-height:21px;color:#6B7280;">If you did not request this password reset, you can ignore this email. Your current password will remain unchanged.</p>
              </td>
            </tr>
          </table>
        </td>
      </tr>
    </table>
  </body>
</html>`

  return {
    to: data.to,
    subject: 'Reset your School Finder AI password',
    html,
    text,
  }
}
