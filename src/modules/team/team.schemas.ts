import { extendZodWithOpenApi } from '@asteasolutions/zod-to-openapi'
import { z } from 'zod'

extendZodWithOpenApi(z)

export class TeamSchemas {
    static invitationSchema = z.object({
        fullName: z.string().trim().min(2),
        email: z.string().trim().min(2).max(160).email(),
        role: z.enum(["ADMIN", "ADVISOR", "OPERATIONS"]),
        phone: z.string().trim().min(3).max(40).nullable().optional(),

    }).refine((data) => data.fullName && data.email, {
        message: "Full name and email are required"
    })
}