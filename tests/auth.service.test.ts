import { beforeEach, describe, expect, it, vi } from 'vitest'
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
const hashRefreshTokenMock =  vi.mocked(hashRefreshToken)

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

describe('AuthService.Login', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    authRepoMock.findUser.mockResolvedValue(activeUser)
    authRepoMock.createAuthSession.mockResolvedValue({
      id: 'session-id',
      expires_at: new Date('2026-07-01T00:00:00.000Z'),
    })
    authRepoMock.updateLastLogin.mockResolvedValue(undefined)
    verifyPasswordMock.mockResolvedValue(true)
    generateRefreshTokenMock.mockReturnValue('raw-refresh-token')
    hashRefreshTokenMock.mockResolvedValue('hashed-refresh-token')
    generateAcessTokenMock.mockReturnValue('access-token')
  })

  it('stores only the hashed refresh token and returns the raw refresh token for the cookie', async () => {
    const result = await AuthService.Login(
      { email: 'admin@example.com', password: 'correct-password', userAgent:  'vitest-agent', ipAddress: '127.0.0.1'},
    )

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
      AuthService.Login(
        { email: 'missing@example.com', password: 'correct-password', userAgent:"", ipAddress:""  },
      ),
    ).rejects.toMatchObject({
      statusCode: 401,
      code: AUTH_ERROR_CODES.INVALID_CREDENTIALS,
      message: 'Invalid email or password',
    })
  })

  it('rejects invalid passwords with a generic credentials error', async () => {
    verifyPasswordMock.mockResolvedValue(false)

    await expect(
      AuthService.Login(
        { email: 'admin@example.com', password: 'wrong-password',  userAgent:"", ipAddress:"" },
      ),
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
      AuthService.Login(
        { email: 'admin@example.com', password: 'correct-password', userAgent:"", ipAddress:""  },
      ),
    ).rejects.toMatchObject({
      statusCode: 403,
      code: AUTH_ERROR_CODES.ACCOUNT_DISABLED,
    })
  })
})
