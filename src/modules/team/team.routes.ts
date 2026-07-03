import express, {type Router} from "express"
import {TeamController} from "./team.controller"
import {TeamSchemas} from "./team.schemas"
import { validate } from "../../middleware/validate"
import { AuthenticateMiddleware } from "../../middleware/authenticate"

export const teamRouter:Router = express.Router() 

teamRouter.post(
"/invitations",
validate(TeamSchemas.invitationSchema),
AuthenticateMiddleware,  
TeamController.Invitations)