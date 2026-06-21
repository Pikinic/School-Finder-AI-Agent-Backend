import type { NextFunction, Request, Response } from 'express'
import type { z } from 'zod'
import { createError } from '../common/errors/AppError'

export const validate =
  (schema: z.ZodObject) =>
  (req: Request, _res: Response, next: NextFunction) => {
    const requestEnvironment = schema.safeParse(req.body)

    if (!requestEnvironment.success) {
      return next(
        createError(
          'Validation failed',
          400,
          { issues: requestEnvironment.error.issues },
          'VALIDATION_ERROR',
        ),
      )
    }

    req.body = requestEnvironment.data
    next()
  }
