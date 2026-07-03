import {Request, Response, NextFunction} from "express"
import { TeamService } from "./team.service"
import {InvitationData} from "./team.types"
import { AccessTokenClaims } from "../auth/auth.types"
import { successResponse } from "../../http/response"

export class TeamController  {
    static Invitations =  async(req: Request, res: Response, next: NextFunction)=>{
      try {
        const sendInvitation = await TeamService.Invitation(req.auth as AccessTokenClaims, req.body as InvitationData)
        res.status(200).send(successResponse(
            true,
            'Invitation sent successfully',
            sendInvitation,
            {requestId:req.id}   
        ))
      }catch (error) {
        next(error)
      }
    }
}