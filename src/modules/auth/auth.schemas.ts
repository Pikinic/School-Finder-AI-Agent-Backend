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

export { loginSchema, forgetPasswordSchema }
