import { NextFunction, Request, Response } from "express"
export const clientInfo =   (req:Request, res:Response, next:NextFunction)=>{
      req.body.ipAddress = req.ip
   req.body.userAgent = req.headers['user-agent']
   next()
} 