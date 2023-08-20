import express from "express"
import rateLimit from "express-rate-limit";
import helmet from "helmet";
import mongoSanitize from "express-mongo-sanitize";
import {xss} from "express-xss-sanitizer";
import hpp from 'hpp'
import * as path from "path";
import {AppError} from "./utils/appError.js";
import {userRouter} from "./routes/userRouter.js";

export const app = express()

// add headers for secure
app.use(helmet())

// save as json

app.use(express.json())

// limit requests
const limiter = rateLimit({
    max: 100,
    widowMs: 60 * 60 * 1000,
    message: 'Too many requests from this IP,please try again in an hour'
})

app.use('/api', limiter)


// disable queries in json
app.use(mongoSanitize())

// disabling html sending
app.use(xss())

// prevent multiple parameters
app.use(hpp({
    whitelist: ['endDays']
}))

app.use(express.static('public'))

// routes
app.use('/api/v1/users', userRouter)

app.all('*', (req, res, next) => {
    next(new AppError(`Can't find ${req.originalUrl} in this server`, 404))
})
