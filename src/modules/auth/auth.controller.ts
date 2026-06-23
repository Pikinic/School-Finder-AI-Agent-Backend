import type { NextFunction, Request, Response } from 'express'
import env from '../../config/env'
import { successResponse } from '../../http/response'
import AuthService from './auth.service'
import { setCookie } from '../../http/cookie'



class AuthController {
  static Login = async (req: Request, res: Response, next: NextFunction) => {
    try {
       const loginUser = await AuthService.Login(
       req.body 
      )

      setCookie(res, loginUser.refreshToken)
      res.status(200).send(
        successResponse(true, 'Login successful', loginUser.data, {
          requestId: req.id,
        }),
      )
    } catch (err) {
      next(err)
    }
  }
  static Refresh = async (req:Request, res:Response, next:NextFunction)=> {
    try{
       const refreshToken = await AuthService.Refresh(req.body)
      setCookie(res, refreshToken.newRefreshToken)
      res.status(200).send(successResponse(true, 'Refresh successful',  {accessToken: refreshToken.accessToken}))
    }catch(error){
        next(error)
    }

  }

}

export default AuthController
