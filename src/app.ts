import express, {Express} from 'express'
import cors from 'cors'
import cookieParser from 'cookie-parser'
import helmet from 'helmet'
import env from "./config/env"

const app:Express = express()

app.use(cors())
app.use(express.json())
app.use(cookieParser(env.cookieSecret))
app.use(helmet())


app.get("/", (_, res)=>{
    res.send("Hello World")
})

export default app