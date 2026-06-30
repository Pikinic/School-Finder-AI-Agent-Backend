type ApiSuccessResponse<T> = {
  success: boolean
  message: string
  data?: T
  meta?: Record<string, unknown>
}

export const successResponse = <T>(
  success: boolean,
  message: string,
  data?: T,
  meta?: Record<string, unknown>,
): ApiSuccessResponse<T> => {
  return {
    success,
    message,
    ...(data !== undefined && { data }),
    ...(meta !== undefined && { meta }),
  }
}
