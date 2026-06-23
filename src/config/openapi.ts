import {
  OpenAPIRegistry,
  OpenApiGeneratorV31,
} from '@asteasolutions/zod-to-openapi'
import { z } from 'zod'
import { loginSchema } from '../modules/auth/auth.schemas'

const registry = new OpenAPIRegistry()

registry.registerComponent('securitySchemes', 'bearerAuth', {
  type: 'http',
  scheme: 'bearer',
  bearerFormat: 'JWT',
})

const errorResponseSchema = registry.register(
  'ErrorResponse',
  z.object({
    success: z.literal(false),
    error: z.object({
      message: z.string(),
      code: z.string(),
      requestId: z.string(),
      details: z.unknown().optional(),
    }),
  }),
)

const loginResponseSchema = registry.register(
  'LoginResponse',
  z.object({
    success: z.literal(true),
    message: z.string(),
    data: z.object({
      accessToken: z.string(),
      user: z.object({
        publicId: z.string(),
        fullName: z.string(),
        email: z.string().email(),
        role: z.enum(['ADMIN', 'ADVISOR', 'OPERATIONS']),
        status: z.enum(['INVITED', 'ACTIVE', 'DISABLED']),
      }),
    }),
    meta: z.object({
      requestId: z.string(),
    }),
  }),
)

const refreshResponseSchema = registry.register(
  'RefreshResponse',
  z.object({
    success: z.literal(true),
    message: z.string(),
    data: z.object({
      accessToken: z.string(),
    }),
    meta: z.object({
      requestId: z.string(),
    }),
  }),
)

const registeredLoginSchema = registry.register('LoginRequest', loginSchema)
const refreshCookieParameter = z.object({
  refreshToken: z
    .string()
    .length(128)
    .openapi({
      description: 'Opaque refresh token issued by login or refresh.',
      param: {
        description: 'Opaque refresh token issued by login or refresh.',
      },
    }),
})

registry.registerPath({
  method: 'post',
  path: '/api/v1/auth/login',
  tags: ['Auth'],
  summary: 'Log in a staff user',
  description:
    'Validates staff credentials, creates a refresh-token session, sets an HttpOnly refreshToken cookie, and returns a short-lived access token.',
  request: {
    body: {
      required: true,
      content: {
        'application/json': {
          schema: registeredLoginSchema,
        },
      },
    },
  },
  responses: {
    200: {
      description:
        'Login successful. The refresh token is returned as an HttpOnly cookie.',
      headers: {
        'Set-Cookie': {
          schema: { type: 'string' },
          description: 'HttpOnly refreshToken cookie; Secure in production.',
        },
      },
      content: {
        'application/json': {
          schema: loginResponseSchema,
        },
      },
    },
    400: {
      description: 'Request validation failed.',
      content: {
        'application/json': {
          schema: errorResponseSchema,
        },
      },
    },
    401: {
      description: 'Invalid email or password.',
      content: {
        'application/json': {
          schema: errorResponseSchema,
        },
      },
    },
    403: {
      description: 'Account is not active.',
      content: {
        'application/json': {
          schema: errorResponseSchema,
        },
      },
    },
  },
})

registry.registerPath({
  method: 'post',
  path: '/api/v1/auth/refresh',
  tags: ['Auth'],
  summary: 'Refresh a staff access token',
  description:
    'Reads the opaque refresh token from the HttpOnly refreshToken cookie, validates the stored session, rotates the refresh-token hash on the same session row, sets a new refreshToken cookie, and returns a new short-lived access token.',
  request: {
    cookies: refreshCookieParameter,
  },
  responses: {
    200: {
      description:
        'Refresh successful. The stored refresh-token hash is replaced and a rotated HttpOnly cookie is returned.',
      headers: {
        'Set-Cookie': {
          schema: { type: 'string' },
          description:
            'Rotated HttpOnly refreshToken cookie; Secure in production.',
        },
      },
      content: {
        'application/json': {
          schema: refreshResponseSchema,
        },
      },
    },
    400: {
      description: 'Refresh cookie is missing or malformed.',
      content: {
        'application/json': {
          schema: errorResponseSchema,
        },
      },
    },
    401: {
      description:
        'Refresh session was not found, expired, revoked, or failed fingerprint validation.',
      content: {
        'application/json': {
          schema: errorResponseSchema,
        },
      },
    },
    403: {
      description: 'Account is not active.',
      content: {
        'application/json': {
          schema: errorResponseSchema,
        },
      },
    },
  },
})

export const openApiDocument = new OpenApiGeneratorV31(
  registry.definitions,
).generateDocument({
  openapi: '3.1.0',
  info: {
    title: 'School Finder Backend API',
    version: '1.0.0',
  },
  servers: [
    {
      url: '/api/v1',
      description: 'Current API version',
    },
  ],
})
