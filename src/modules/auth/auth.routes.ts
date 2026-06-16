import { Router } from "express";

export const authRouter = Router()


authRouter.post("/invitations/:token")
