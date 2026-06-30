import app from './app'
import http from 'http'
import env from './config/env'
import { logger } from './config/logger'

const server = http.createServer(app)

server.listen(env.port, () => {
  logger.info({ port: env.port }, 'Server started')
})

process.on('SIGABRT', () => {
  logger.info('Server closing')
  server.close(() => {
    process.exit(0)
  })
})
