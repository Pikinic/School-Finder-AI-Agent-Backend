import type { NextFunction, Request, Response } from 'express'

export const clientInfo = (
  req: Request,
  _res: Response,
  next: NextFunction,
) => {
  const body =
    typeof req.body === 'object' && req.body !== null
      ? (req.body as Record<string, unknown>)
      : {}

  body.ipAddress = req.ip ?? null
  body.userAgent = req.get('user-agent') ?? null
  req.body = body
  next()
}
