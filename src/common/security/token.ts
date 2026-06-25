import jwt from "jsonwebtoken"
import env from "../../config/env"
import crypto from "crypto"
import { createError } from "../errors/AppError"
import { AUTH_ERROR_CODES } from "../errors/errorCodes"

const generateAcessToken = (sub: string, session_Id:string, role: string, token_version:number):string =>{
    const token = jwt.sign({sub, session_Id, role, token_version}, env.jwtSecret, {expiresIn: "15m"})
 return token
}

const  decodeAcessToken =  (token:string)=>{
   try {
       const decoded = jwt.verify(token, env.jwtSecret)
        return decoded
   } catch (error) {
       if(error instanceof Error){

         console.log(error.message)
         if (error.message == 'jwt must be provided' || error.message == 'jwt malformed'){
           throw createError('Unable to autheticate user', 401, {}, AUTH_ERROR_CODES.ACCESS_TOKEN_MALFORMED)
         }else if(error.message == 'jwt expired'){
            throw createError('Unable to autheticate user', 401, {}, AUTH_ERROR_CODES.ACCESS_TOKEN_EXPIRED)
         }else if(error.message == 'invalid signature'){
            throw createError('Unable to autheticate user', 401, {}, AUTH_ERROR_CODES.ACCESS_TOKEN_INVALID)
         }else{
            throw createError('Unable to autheticate user', 401, {}, AUTH_ERROR_CODES.ACCESS_TOKEN_INVALID)
         }
        
       }
       
   }
 
}
const generateRefreshToken = ():string=>{
   return crypto.randomBytes(64).toString("hex")
}

export {generateAcessToken, decodeAcessToken, generateRefreshToken}