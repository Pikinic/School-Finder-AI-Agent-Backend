import { extendZodWithOpenApi } from '@asteasolutions/zod-to-openapi'
import { z } from 'zod'

extendZodWithOpenApi(z)

const loginSchema = z.object({
  email: z.string().trim().min(2).max(160).email(),
  password: z.string().min(12),
})

const forgetPasswordSchema = z.object({
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

export {
  loginSchema,
  forgetPasswordSchema,
  refreshTokenSchema,
  editUserDetailsSchema,
}
