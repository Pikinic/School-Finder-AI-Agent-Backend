import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { AUTH_ERROR_CODES } from '../src/common/errors/errorCodes'
import { verifyPassword } from '../src/common/security/password'
import {
  generateAcessToken,
  generateRefreshToken,
} from '../src/common/security/token'
import { hashRefreshToken } from '../src/common/security/tokenHash'
import AuthRepo from '../src/modules/auth/auth.repository'
import AuthService from '../src/modules/auth/auth.service'

vi.mock('../src/modules/auth/auth.repository', () => ({
  default: {
    findUser: vi.fn(),
    createAuthSession: vi.fn(),
    updateLastLogin: vi.fn(),
    findAuthSession: vi.fn(),
    rotateRefreshToken: vi.fn(),
    revokeAuthSession: vi.fn(),
    revokeAuthSessionFamily: vi.fn(),
    findAuthSessionById: vi.fn(),
    updateUserDetails: vi.fn(),
  },
}))

vi.mock('../src/common/security/password', () => ({
  verifyPassword: vi.fn(),
}))

vi.mock('../src/common/security/token', () => ({
  generateAcessToken: vi.fn(),
  generateRefreshToken: vi.fn(),
}))

vi.mock('../src/common/security/tokenHash', () => ({
  hashRefreshToken: vi.fn(),
}))

const authRepoMock = vi.mocked(AuthRepo)
const verifyPasswordMock = vi.mocked(verifyPassword)
const generateAcessTokenMock = vi.mocked(generateAcessToken)
const generateRefreshTokenMock = vi.mocked(generateRefreshToken)
const hashRefreshTokenMock = vi.mocked(hashRefreshToken)

const activeUser = {
  id: '78bd6894-d3d7-405b-9443-17d376b50db1',
  public_id: 'usr_123',
  full_name: 'Admin User',
  email: 'admin@example.com',
  phone: null,
  password_hash: 'argon-hash',
  role: 'ADMIN',
  status: 'ACTIVE',
  last_login_at: null,
  password_changed_at: null,
  token_version: 0,
  created_at: new Date('2026-06-01T00:00:00.000Z'),
  updated_at: new Date('2026-06-01T00:00:00.000Z'),
} as const

const activeSession = {
  id: 'session-id',
  user_id: activeUser.id,
  refresh_token_hash: 'hashed-refresh-token',
  token_family: 'token-family-id',
  user_agent: 'vitest-agent',
  ip_address: '127.0.0.1',
  expires_at: new Date('2026-07-01T00:00:00.000Z'),
  revoked_at: null,
  last_used_at: null,
  created_at: new Date('2026-06-01T00:00:00.000Z'),
} as const

describe('AuthService.Login', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    authRepoMock.findUser.mockResolvedValue(activeUser)
    authRepoMock.createAuthSession.mockResolvedValue({
      id: 'session-id',
      expires_at: new Date('2026-07-01T00:00:00.000Z'),
    })
    authRepoMock.updateLastLogin.mockResolvedValue(undefined)
    authRepoMock.findAuthSession.mockResolvedValue(activeSession)
    authRepoMock.rotateRefreshToken.mockResolvedValue({
      ...activeSession,
      refresh_token_hash: 'new-hashed-refresh-token',
      last_used_at: new Date('2026-06-15T00:00:00.000Z'),
    })
    authRepoMock.revokeAuthSession.mockResolvedValue(undefined)
    authRepoMock.revokeAuthSessionFamily.mockResolvedValue(undefined)
    verifyPasswordMock.mockResolvedValue(true)
    generateRefreshTokenMock.mockReturnValue('raw-refresh-token')
    hashRefreshTokenMock.mockReturnValue('hashed-refresh-token')
    generateAcessTokenMock.mockReturnValue('access-token')
  })

  it('stores only the hashed refresh token and returns the raw refresh token for the cookie', async () => {
    const result = await AuthService.Login({
      email: 'admin@example.com',
      password: 'correct-password',
      userAgent: 'vitest-agent',
      ipAddress: '127.0.0.1',
    })

    expect(hashRefreshTokenMock).toHaveBeenCalledWith('raw-refresh-token')
    expect(authRepoMock.createAuthSession).toHaveBeenCalledWith(
      expect.objectContaining({
        user_id: activeUser.id,
        refreshTokenHash: 'hashed-refresh-token',
        userAgent: 'vitest-agent',
        ipAddress: '127.0.0.1',
      }),
    )
    expect(result.refreshToken).toBe('raw-refresh-token')
    expect(result.data).toEqual({
      accessToken: 'access-token',
      user: {
        publicId: 'usr_123',
        fullName: 'Admin User',
        email: 'admin@example.com',
        role: 'ADMIN',
        status: 'ACTIVE',
      },
    })
    expect(authRepoMock.updateLastLogin).toHaveBeenCalledWith(activeUser.id)
  })

  it('rejects unknown users with a generic credentials error', async () => {
    authRepoMock.findUser.mockResolvedValue(null)

    await expect(
      AuthService.Login({
        email: 'missing@example.com',
        password: 'correct-password',
        userAgent: '',
        ipAddress: '',
      }),
    ).rejects.toMatchObject({
      statusCode: 401,
      code: AUTH_ERROR_CODES.INVALID_CREDENTIALS,
      message: 'Invalid email or password',
    })
  })

  it('rejects invalid passwords with a generic credentials error', async () => {
    verifyPasswordMock.mockResolvedValue(false)

    await expect(
      AuthService.Login({
        email: 'admin@example.com',
        password: 'wrong-password',
        userAgent: '',
        ipAddress: '',
      }),
    ).rejects.toMatchObject({
      statusCode: 401,
      code: AUTH_ERROR_CODES.INVALID_CREDENTIALS,
      message: 'Invalid email or password',
    })
  })

  it('rejects inactive accounts', async () => {
    authRepoMock.findUser.mockResolvedValue({
      ...activeUser,
      status: 'DISABLED',
    })

    await expect(
      AuthService.Login({
        email: 'admin@example.com',
        password: 'correct-password',
        userAgent: '',
        ipAddress: '',
      }),
    ).rejects.toMatchObject({
      statusCode: 403,
      code: AUTH_ERROR_CODES.ACCOUNT_DISABLED,
    })
  })
})

describe('AuthService.Refresh', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.useFakeTimers()
    vi.setSystemTime(new Date('2026-06-15T00:00:00.000Z'))

    authRepoMock.findAuthSession.mockResolvedValue(activeSession)
    authRepoMock.findUser.mockResolvedValue(activeUser)
    authRepoMock.rotateRefreshToken.mockResolvedValue({
      ...activeSession,
      refresh_token_hash: 'new-hashed-refresh-token',
      last_used_at: new Date('2026-06-15T00:00:00.000Z'),
    })
    authRepoMock.revokeAuthSession.mockResolvedValue(undefined)
    authRepoMock.revokeAuthSessionFamily.mockResolvedValue(undefined)
    hashRefreshTokenMock
      .mockReturnValueOnce('hashed-refresh-token')
      .mockReturnValueOnce('new-hashed-refresh-token')
    generateRefreshTokenMock.mockReturnValue('new-raw-refresh-token')
    generateAcessTokenMock.mockReturnValue('new-access-token')
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  it('rotates the refresh token and returns a new access token', async () => {
    const result = await AuthService.Refresh({
      refreshToken: 'raw-refresh-token',
      ipAddress: '127.0.0.1',
      userAgent: 'vitest-agent',
    })

    expect(hashRefreshTokenMock).toHaveBeenNthCalledWith(1, 'raw-refresh-token')
    expect(authRepoMock.findAuthSession).toHaveBeenCalledWith(
      'hashed-refresh-token',
    )
    expect(generateAcessTokenMock).toHaveBeenCalledWith(
      activeUser.id,
      activeSession.id,
      activeUser.role,
      activeUser.token_version,
    )
    expect(authRepoMock.rotateRefreshToken).toHaveBeenCalledWith({
      authSessionId: activeSession.id,
      lastUsedAt: new Date('2026-06-15T00:00:00.000Z'),
      hashedRefreshToken: 'new-hashed-refresh-token',
    })
    expect(result).toEqual({
      newRefreshToken: 'new-raw-refresh-token',
      accessToken: 'new-access-token',
    })
  })

  it('rejects an unknown refresh token', async () => {
    authRepoMock.findAuthSession.mockResolvedValue(null)

    await expect(
      AuthService.Refresh({
        refreshToken: 'missing-token',
        ipAddress: '127.0.0.1',
        userAgent: 'vitest-agent',
      }),
    ).rejects.toMatchObject({
      statusCode: 401,
      code: AUTH_ERROR_CODES.AUTH_SESSION_NOT_FOUND,
    })
    expect(authRepoMock.rotateRefreshToken).not.toHaveBeenCalled()
  })

  it('rejects expired sessions', async () => {
    authRepoMock.findAuthSession.mockResolvedValue({
      ...activeSession,
      expires_at: new Date('2026-06-01T00:00:00.000Z'),
    })

    await expect(
      AuthService.Refresh({
        refreshToken: 'raw-refresh-token',
        ipAddress: '127.0.0.1',
        userAgent: 'vitest-agent',
      }),
    ).rejects.toMatchObject({
      statusCode: 401,
      code: AUTH_ERROR_CODES.AUTH_SESSION_EXPIRED,
    })
    expect(authRepoMock.revokeAuthSession).toHaveBeenCalledWith(
      activeSession.id,
    )
  })

  it('rejects revoked sessions', async () => {
    authRepoMock.findAuthSession.mockResolvedValue({
      ...activeSession,
      revoked_at: new Date('2026-06-10T00:00:00.000Z'),
    })

    await expect(
      AuthService.Refresh({
        refreshToken: 'raw-refresh-token',
        ipAddress: '127.0.0.1',
        userAgent: 'vitest-agent',
      }),
    ).rejects.toMatchObject({
      statusCode: 401,
      code: AUTH_ERROR_CODES.AUTH_SESSION_REVOKED,
    })
    expect(authRepoMock.revokeAuthSessionFamily).not.toHaveBeenCalled()
  })

  it('rejects inactive users', async () => {
    authRepoMock.findUser.mockResolvedValue({
      ...activeUser,
      status: 'DISABLED',
    })

    await expect(
      AuthService.Refresh({
        refreshToken: 'raw-refresh-token',
        ipAddress: '127.0.0.1',
        userAgent: 'vitest-agent',
      }),
    ).rejects.toMatchObject({
      statusCode: 403,
      code: AUTH_ERROR_CODES.ACCOUNT_DISABLED,
    })
  })

  it('rejects session fingerprint mismatch', async () => {
    await expect(
      AuthService.Refresh({
        refreshToken: 'raw-refresh-token',
        ipAddress: '127.0.0.1',
        userAgent: 'different-agent',
      }),
    ).rejects.toMatchObject({
      statusCode: 401,
      code: AUTH_ERROR_CODES.AUTH_SESSION_DEVICE_MISMATCH,
    })
    expect(authRepoMock.revokeAuthSession).toHaveBeenCalledWith(
      activeSession.id,
    )
  })
})

describe('AuthService.Logout', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    hashRefreshTokenMock.mockReset()
    authRepoMock.findAuthSession.mockResolvedValue(activeSession)
    authRepoMock.revokeAuthSession.mockResolvedValue(undefined)
    hashRefreshTokenMock.mockReturnValue('hashed-refresh-token')
  })

  it('revokes the current refresh-token session', async () => {
    await AuthService.Logout({
      sub: activeUser.id,
      session_Id: activeSession.id,
      role: activeUser.role,
      token_version: activeUser.token_version,
      refreshToken: 'raw-refresh-token',
    })

    expect(hashRefreshTokenMock).toHaveBeenCalledWith('raw-refresh-token')
    expect(authRepoMock.findAuthSession).toHaveBeenCalledWith(
      'hashed-refresh-token',
    )
    expect(authRepoMock.revokeAuthSession).toHaveBeenCalledWith(
      activeSession.id,
    )
  })

  it('rejects missing refresh-token sessions', async () => {
    authRepoMock.findAuthSession.mockResolvedValue(null)

    await expect(
      AuthService.Logout({
        sub: activeUser.id,
        session_Id: activeSession.id,
        role: activeUser.role,
        token_version: activeUser.token_version,
        refreshToken: 'raw-refresh-token',
      }),
    ).rejects.toMatchObject({
      statusCode: 401,
      code: AUTH_ERROR_CODES.AUTH_SESSION_NOT_FOUND,
    })
    expect(authRepoMock.revokeAuthSession).not.toHaveBeenCalled()
  })

  it('rejects refresh sessions that do not match the access token', async () => {
    await expect(
      AuthService.Logout({
        sub: activeUser.id,
        session_Id: 'different-session-id',
        role: activeUser.role,
        token_version: activeUser.token_version,
        refreshToken: 'raw-refresh-token',
      }),
    ).rejects.toMatchObject({
      statusCode: 401,
      code: AUTH_ERROR_CODES.AUTH_SESSION_DEVICE_MISMATCH,
    })
    expect(authRepoMock.revokeAuthSession).not.toHaveBeenCalled()
  })
})

describe('AuthService.LogoutAll', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    hashRefreshTokenMock.mockReset()
    authRepoMock.findAuthSession.mockResolvedValue(activeSession)
    authRepoMock.revokeAuthSessionFamily.mockResolvedValue(undefined)
    hashRefreshTokenMock.mockReturnValue('hashed-refresh-token')
  })

  it('revokes all active sessions for the authenticated user', async () => {
    await AuthService.LogoutAll({
      sub: activeUser.id,
      session_Id: activeSession.id,
      role: activeUser.role,
      token_version: activeUser.token_version,
      refreshToken: 'raw-refresh-token',
    })

    expect(authRepoMock.revokeAuthSessionFamily).toHaveBeenCalledWith(
      activeUser.id,
    )
  })

  it('rejects refresh sessions owned by another user', async () => {
    await expect(
      AuthService.LogoutAll({
        sub: 'different-user-id',
        session_Id: activeSession.id,
        role: activeUser.role,
        token_version: activeUser.token_version,
        refreshToken: 'raw-refresh-token',
      }),
    ).rejects.toMatchObject({
      statusCode: 401,
      code: AUTH_ERROR_CODES.AUTH_SESSION_DEVICE_MISMATCH,
    })
    expect(authRepoMock.revokeAuthSessionFamily).not.toHaveBeenCalled()
  })
})

describe('AuthService.UserDetails', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    authRepoMock.findUser.mockResolvedValue(activeUser)
  })

  it('returns the safe authenticated user shape', async () => {
    const result = await AuthService.UserDetails({
      sub: activeUser.id,
      session_Id: activeSession.id,
      role: activeUser.role,
      token_version: activeUser.token_version,
    })

    expect(result).toEqual({
      public_id: activeUser.public_id,
      full_name: activeUser.full_name,
      email: activeUser.email,
      phone: activeUser.phone,
      role: activeUser.role,
      status: activeUser.status,
      last_login_at: activeUser.last_login_at,
      created_at: activeUser.created_at,
      updated_at: activeUser.updated_at,
    })
    expect(result).not.toHaveProperty('password_hash')
    expect(result).not.toHaveProperty('token_version')
  })
})

describe('AuthService.EditUserDetails', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    authRepoMock.findUser.mockResolvedValue(activeUser)
    authRepoMock.updateUserDetails.mockResolvedValue({
      ...activeUser,
      full_name: 'Updated Admin',
      phone: '+2348012345678',
      updated_at: new Date('2026-06-20T00:00:00.000Z'),
    })
  })

  it('updates editable profile fields and returns the safe user shape', async () => {
    const result = await AuthService.EditUserDetails(
      {
        sub: activeUser.id,
        session_Id: activeSession.id,
        role: activeUser.role,
        token_version: activeUser.token_version,
      },
      {
        fullName: 'Updated Admin',
        phone: '+2348012345678',
      },
    )

    expect(authRepoMock.findUser).toHaveBeenCalledWith({ id: activeUser.id })
    expect(authRepoMock.updateUserDetails).toHaveBeenCalledWith(activeUser.id, {
      fullName: 'Updated Admin',
      phone: '+2348012345678',
    })
    expect(result).toEqual({
      public_id: activeUser.public_id,
      full_name: 'Updated Admin',
      email: activeUser.email,
      phone: '+2348012345678',
      role: activeUser.role,
      status: activeUser.status,
      last_login_at: activeUser.last_login_at,
      created_at: activeUser.created_at,
      updated_at: new Date('2026-06-20T00:00:00.000Z'),
    })
    expect(result).not.toHaveProperty('password_hash')
    expect(result).not.toHaveProperty('token_version')
  })

  it('rejects missing users', async () => {
    authRepoMock.findUser.mockResolvedValue(null)

    await expect(
      AuthService.EditUserDetails(
        {
          sub: activeUser.id,
          session_Id: activeSession.id,
          role: activeUser.role,
          token_version: activeUser.token_version,
        },
        { fullName: 'Updated Admin' },
      ),
    ).rejects.toMatchObject({
      statusCode: 401,
      code: AUTH_ERROR_CODES.INVALID_CREDENTIALS,
    })
    expect(authRepoMock.updateUserDetails).not.toHaveBeenCalled()
  })
})
