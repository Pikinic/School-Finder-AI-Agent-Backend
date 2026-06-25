import { NextFunction, Request, Response } from "express"
import { decodeAcessToken } from "../common/security/token"
import { createError } from "../common/errors/AppError"
import { AUTH_ERROR_CODES } from "../common/errors/errorCodes"
export const AuthenticateMiddleware = async (req:Request, res:Response, next:NextFunction)=>{
try {
    const accessToken = req.headers.authorization?.split(" ")[1] as string
  
    if(accessToken == ""){
        return next(createError("Not authorized", 401, {}, AUTH_ERROR_CODES.TOKEN_INVALID))
       
    }

    const tokenData =  decodeAcessToken(accessToken)
    console.log(tokenData)
    req.body = tokenData
    next()

} catch (error) {
  next(error)
}
}