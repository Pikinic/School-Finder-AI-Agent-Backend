import app from './app'
import  http from 'http'
import env from './config/env'


const server  = http.createServer(app)

server.listen(env.port, ()=>{
    console.log(`Server is running on port ${env.port}`)
})



process.on('SIGABRT', ()=>{
    console.log('Server closed')
    server.close(()=>{
        process.exit(0)
    })
})