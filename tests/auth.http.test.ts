import './setup-env'
import type { Express } from 'express'
import request from 'supertest'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import app from '../src/app'
import AuthService from '../src/modules/auth/auth.service'

vi.mock('../src/modules/auth/auth.service', () => ({
  default: {
    Login: vi.fn(),
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

type ErrorResponseBody = {
  message: string
  code: string
  requestId: unknown
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
    const setCookie = response.headers['set-cookie'] as unknown as
      | string[]
      | undefined

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
    expect(setCookie?.[0]).toContain('refreshToken=raw-refresh-token')
    expect(setCookie?.[0]).toContain('HttpOnly')
    expect(AuthService.Login).toHaveBeenCalledWith(
      { email: 'admin@example.com', password: 'correct-password' },
      'vitest-agent',
      expect.any(String),
    )
  })

  it('returns a stable validation error response', async () => {
    const response = await request(testApp)
      .post('/api/v1/auth/login')
      .send({ email: 'not-an-email', password: 'short' })
      .expect(400)

    const responseBody = response.body as unknown as ErrorResponseBody

    expect(responseBody).toMatchObject({
      message: 'Validation failed',
      code: 'VALIDATION_ERROR',
    })
    expect(typeof responseBody.requestId).toBe('string')
  })
})
