export interface AppError extends Error {
  statusCode: number
  code: string
  details?: unknown
}

export const createError = (
  message: string,
  statusCode: number,
  details: unknown,
  code: string,
): AppError => {
  const error = new Error(message) as AppError
  error.statusCode = statusCode
  error.code = code
  error.details = details

  return error
}
