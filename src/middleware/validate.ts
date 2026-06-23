import type { NextFunction, Request, Response } from 'express'
import type { z } from 'zod'
import { createError } from '../common/errors/AppError'
import cookieParser from 'cookie-parser'
import { AUTH_ERROR_CODES } from '../common/errors/errorCodes'

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


  export const validateRefreshToken =(schema:z.ZodObject)=> (req:Request, res:Response, next:NextFunction)=>{
  
    console.log(req.cookies, "kjhgfd")
    const validate = schema.safeParse(req.cookies)
    console.log(validate)
    if(!validate.success){
       return next(
        createError(
          'Refresh token is required',
          400,
          {},
          AUTH_ERROR_CODES.UNAUTHORIZED,
        ))
    }
    
    req.body = validate.data
    next()
    
  }