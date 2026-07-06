
import prisma from "../../database/prisma";
import { CreateAndInviteData } from "./team.types";

class TeamRepo {
    
    static async CreateInviteUser (data:CreateAndInviteData){
    return prisma.$transaction(async (tx) => {
        const user = await tx.users.create({
            data:{
            public_id:data.publicId,
            full_name:data.fullName,
             email:data.email,
             role:data.role,
             status:data.status,
            }
         
        })

      const invite = await tx.team_Invitations.create({
         data:{
            user_id:user.id,
            invited_by_user_id:data.adminId,
            token_hash:data.token_hash,
            expires_at:data.expiresAt,
            sent_at:data.sent_at,
            last_sent_at:data.last_sent_at
         }
      })
      return {user, invite}
    })
}
   static async FindTeamInvitation (tokenHash:string){
        return await prisma.team_Invitations.findUnique({
            where:{
                token_hash:tokenHash
            },
           include:{
            user:true
           }
        })


    }

    
}

export default TeamRepo