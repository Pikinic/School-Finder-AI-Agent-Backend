import jwt from "jsonwebtoken"
import env from "../../config/env"
import crypto from "crypto"

const generateAcessToken = (sub: string, session_Id:string, role: string, token_version:number):string =>{
    const token = jwt.sign({sub, session_Id, role, token_version}, env.jwtSecret, {expiresIn: "15m"})
 return token
}

const generateRefreshToken = ():string=>{
   return crypto.randomBytes(64).toString("hex")
}

export {generateAcessToken, generateRefreshToken}