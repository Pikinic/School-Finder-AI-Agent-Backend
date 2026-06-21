import { randomUUID } from 'node:crypto'
import type { NextFunction, Request, Response } from 'express'

export const requestId = (req: Request, res: Response, next: NextFunction) => {
  const incomingRequestId = req.headers['x-request-id']
  const id =
    typeof incomingRequestId === 'string' && incomingRequestId.length > 0
      ? incomingRequestId
      : randomUUID()

  req.id = id
  res.setHeader('X-Request-Id', id)
  next()
}
