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
    revokeAuthSessionFamily: vi.fn(),
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
    expect(authRepoMock.revokeAuthSessionFamily).toHaveBeenCalledWith(
      activeSession.token_family,
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
    expect(authRepoMock.revokeAuthSessionFamily).toHaveBeenCalledWith(
      activeSession.token_family,
    )
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
    expect(authRepoMock.revokeAuthSessionFamily).toHaveBeenCalledWith(
      activeSession.token_family,
    )
  })
})
