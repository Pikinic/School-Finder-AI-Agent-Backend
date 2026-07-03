type InvitationData = {
 fullName: string
  email: string
  role: 'ADMIN' | 'ADVISOR' | 'OPERATIONS'
  phone?: string | null
}

type CreateAndInviteData = InvitationData & {
    publicId: string
    status: 'INVITED' | 'ACTIVE' | 'DISABLED'
    adminId:string
    token_hash:string
    expiresAt:Date
    sent_at:Date
    last_sent_at:Date   
} 

type InviteEmailData = {
     fullName: string
     inviterName: string
      inviteUrl: string
      to:string
      role: 'ADMIN' | 'ADVISOR' | 'OPERATIONS'
     expiresInMinutes: Date
}




export{
  InvitationData,
    CreateAndInviteData,
    InviteEmailData
}