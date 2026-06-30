import { extendZodWithOpenApi } from '@asteasolutions/zod-to-openapi'
import { z } from 'zod'

extendZodWithOpenApi(z)

const loginSchema = z.object({
  email: z.string().trim().min(2).max(160).email(),
  password: z.string().min(8),
})

const forgotPasswordSchema = z.object({
  email: z.string().trim().min(2).max(160).email(),
})

const refreshTokenSchema = z.object({
  refreshToken: z.string().trim().length(128),
})

const editUserDetailsSchema = z
  .object({
    fullName: z.string().trim().min(2).max(160).optional(),
    phone: z.string().trim().min(3).max(40).nullable().optional(),
  })
  .refine((data) => data.fullName !== undefined || data.phone !== undefined, {
    message: 'At least one profile field is required',
  })

const changePasswordSchema = z
  .object({
    currentPassword: z.string().min(8),
    newPassword: z
      .string()
      .min(8)
      .regex(/[A-Z]/, 'Password must contain at least one uppercase letter')
      .regex(/[a-z]/, 'Password must contain at least one lowercase letter')
      .regex(/[0-9]/, 'Password must contain at least one number'),
    confirmNewPassword: z.string().min(8),
  })
  .refine((data) => data.newPassword === data.confirmNewPassword, {
    message: 'Passwords do not match',
    path: ['confirmNewPassword'],
  })

export {
  loginSchema,
  forgotPasswordSchema,
  refreshTokenSchema,
  editUserDetailsSchema,
  changePasswordSchema,
}
