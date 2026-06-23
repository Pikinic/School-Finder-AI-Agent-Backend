import './setup-env'
import type { Express } from 'express'
import request from 'supertest'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import app from '../src/app'
import AuthService from '../src/modules/auth/auth.service'

vi.mock('../src/modules/auth/auth.service', () => ({
  default: {
    Login: vi.fn(),
    Refresh: vi.fn(),
  },
}))

type LoginResponseBody = {
  success: boolean
  message: string
  data: {
    accessToken: string
    user: {
      publicId: string
      email: string
    }
  }
  meta: {
    requestId: unknown
  }
}

type RefreshResponseBody = {
  success: boolean
  message: string
  data: {
    accessToken: string
  }
  meta: {
    requestId: unknown
  }
}

type ErrorResponseBody = {
  success: false
  error: {
    message: string
    code: string
    requestId: unknown
  }
}

const getFirstSetCookie = (headers: unknown): string | undefined => {
  const headerRecord =
    typeof headers === 'object' && headers !== null
      ? (headers as Record<string, unknown>)
      : {}
  const setCookie = headerRecord['set-cookie']

  if (Array.isArray(setCookie)) {
    const setCookieValues = setCookie as unknown[]
    const firstCookie = setCookieValues[0]
    return typeof firstCookie === 'string' ? firstCookie : undefined
  }

  return typeof setCookie === 'string' ? setCookie : undefined
}

describe('POST /api/v1/auth/login', () => {
  const testApp: Express = app

  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('returns an access token payload and sets an HttpOnly refresh cookie', async () => {
    vi.mocked(AuthService.Login).mockResolvedValue({
      refreshToken: 'raw-refresh-token',
      data: {
        accessToken: 'access-token',
        user: {
          publicId: 'usr_123',
          fullName: 'Admin User',
          email: 'admin@example.com',
          role: 'ADMIN',
          status: 'ACTIVE',
        },
      },
    })

    const response = await request(testApp)
      .post('/api/v1/auth/login')
      .set('User-Agent', 'vitest-agent')
      .send({ email: 'admin@example.com', password: 'correct-password' })
      .expect(200)

    const responseBody = response.body as unknown as LoginResponseBody
    const setCookie = getFirstSetCookie(response.headers)

    expect(responseBody).toMatchObject({
      success: true,
      message: 'Login successful',
      data: {
        accessToken: 'access-token',
        user: {
          publicId: 'usr_123',
          email: 'admin@example.com',
        },
      },
    })
    expect(typeof responseBody.meta.requestId).toBe('string')
    expect(setCookie).toContain('refreshToken=raw-refresh-token')
    expect(setCookie).toContain('HttpOnly')

    const loginRequest = vi.mocked(AuthService.Login).mock.calls[0]?.[0]
    expect(loginRequest).toMatchObject({
      email: 'admin@example.com',
      password: 'correct-password',
      userAgent: 'vitest-agent',
    })
    expect(typeof loginRequest?.ipAddress).toBe('string')
  })

  it('returns a stable validation error response', async () => {
    const response = await request(testApp)
      .post('/api/v1/auth/login')
      .send({ email: 'not-an-email', password: 'short' })
      .expect(400)

    const responseBody = response.body as unknown as ErrorResponseBody

    expect(responseBody.error).toMatchObject({
      message: 'Validation failed',
      code: 'VALIDATION_ERROR',
    })
    expect(typeof responseBody.error.requestId).toBe('string')
  })
})

describe('POST /api/v1/auth/refresh', () => {
  const testApp: Express = app

  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('reads the refresh token from the cookie, rotates it, and returns a new access token', async () => {
    vi.mocked(AuthService.Refresh).mockResolvedValue({
      newRefreshToken: 'new-raw-refresh-token',
      accessToken: 'new-access-token',
    })

    const response = await request(testApp)
      .post('/api/v1/auth/refresh')
      .set('User-Agent', 'vitest-agent')
      .set('Cookie', 'refreshToken=' + 'a'.repeat(128))
      .expect(200)

    const responseBody = response.body as unknown as RefreshResponseBody
    const setCookie = getFirstSetCookie(response.headers)

    expect(responseBody).toMatchObject({
      success: true,
      message: 'Refresh successful',
      data: {
        accessToken: 'new-access-token',
      },
    })
    expect(typeof responseBody.meta.requestId).toBe('string')
    expect(setCookie).toContain('refreshToken=new-raw-refresh-token')
    expect(setCookie).toContain('HttpOnly')

    const refreshRequest = vi.mocked(AuthService.Refresh).mock.calls[0]?.[0]
    expect(refreshRequest).toMatchObject({
      refreshToken: 'a'.repeat(128),
      userAgent: 'vitest-agent',
    })
    expect(typeof refreshRequest?.ipAddress).toBe('string')
  })

  it('rejects requests without a refresh cookie', async () => {
    const response = await request(testApp)
      .post('/api/v1/auth/refresh')
      .expect(400)

    const responseBody = response.body as unknown as ErrorResponseBody

    expect(responseBody.error).toMatchObject({
      message: 'Refresh token is required',
      code: 'UNAUTHORIZED',
    })
    expect(AuthService.Refresh).not.toHaveBeenCalled()
  })
})
