import { createError } from '../../common/errors/AppError';
import { generateOpaqueToken, hashOpaqueToken } from '../../common/security/opaqueToken';
import AuthRepo from '../auth/auth.repository';
import TeamRepo from './team.repository';
import { AccessTokenClaims } from '../auth/auth.types';
import { CreateAndInviteData, InvitationData } from './team.types';
import { createPublicUserId } from '../../common/security/publicId';
import { buildInviteEmail } from '../../integrations/email/email.templates';
import env from '../../config/env';
import EmailProvider from '../../integrations/email/email.provider';
import { logger } from '../../config/logger';

const invitationResetTokenTtlMinutes = 60

export class TeamService {
  static Invitation = async(auth:AccessTokenClaims, invitationData: InvitationData) =>{
      
    const email = invitationData.email.trim().toLowerCase()
     const user = await AuthRepo.findUser({id:auth.sub})

     if(!user || user.status !== 'ACTIVE' ||  user.role !== 'ADMIN'){
        throw createError('User is not authorized to send invitations', 403, {}, 'USER_NOT_AUTHORIZED')
     }

     const token =  generateOpaqueToken()
     const tokenHash =  hashOpaqueToken(token)
     const expiresAt = new Date(Date.now() + invitationResetTokenTtlMinutes * 60 * 1000) // 60 minutes from now
     const sentAt = new Date()

     const data:CreateAndInviteData = {
          publicId: createPublicUserId(),
          fullName: invitationData.fullName,
          email:email,
          phone: invitationData.phone ?? null,
          role: invitationData.role,
          status: 'INVITED',
          adminId: user.id,
          token_hash: tokenHash,
        expiresAt: expiresAt,
        sent_at:sentAt,
         last_sent_at:sentAt,
     }

     const createUserAndInvitation =  await TeamRepo.CreateInviteUser(data)
      
    const setUrl = new URL(`/set-password/${token}`, env.frontendUrl).href
    
    try{
      await EmailProvider.send(
        buildInviteEmail({
        fullName: invitationData.fullName,
        inviterName: user.full_name,
        inviteUrl: setUrl,
        role: invitationData.role,
        to: invitationData.email,
        expiresInMinutes: createUserAndInvitation.invite.expires_at
      }))
    }catch(error){
       logger.error(
        {
        err:error,
        userId:user.id,
        invitationExpiresAt:createUserAndInvitation.invite.expires_at,
        },
        'Failed to send invitation email'
    )
   
    const data = {
        publicId: createUserAndInvitation.user.public_id,
        fullName: createUserAndInvitation.user.full_name,
        email: createUserAndInvitation.user.email,
        role: createUserAndInvitation.user.role,
        status: createUserAndInvitation.user.status,
        expiresAt: createUserAndInvitation.invite.expires_at,
        sentAt: createUserAndInvitation.invite.sent_at,
    }
    return data

    }
  

  }
}