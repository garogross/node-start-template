import {AppError} from "../utils/appError.js";

const sendErrDev = (err, res) => {
    res.status(err.statusCode).json({
        status: err.status,
        message: err.message,
        stack: err.stack,
        error: err
    })
}

const sendErrProd = (err, res) => {
    res.status(err.statusCode).json({
        status: err.status,
        message: err.message,
    })
}

const handleCastErrorDb = (err) => {
    const message = `invalid ${err.path}: ${err.value}`
    return new AppError(message, 400)
}

const handleDuplicateError = (err) => {
    const entries = Object.entries(err.keyValue).map((item,_,arr) => `'${item[1]}' of field '${item[0]}'`).join(',')
    const message = `Duplicated value(s) ${entries}`
    return new AppError(message, 400)
}

const handleJWTError = () => new AppError('Invalid Token,please log in again',401)

const handleJWTExpiredError = () => new AppError('Your token has expired,please log in again')

export const globalErrorHandler = (err, req, res) => {
    err.statusCode = err.statusCode || 500
    err.status = err.status || 'error'

    if (process.env.NODE_ENV === 'development') {
        sendErrDev(err, res)
    } else if (process.env.NODE_ENV === 'production') {
        let error = {...err}
        if(error.name === 'CastError') error = handleCastErrorDb(error)
        if(error.code === 11000) error = handleDuplicateError(error)
        if(error.name === 'JsonWebTokenError') error = handleJWTError()
        if(error.name === 'TokenExpiredError') error = handleJWTExpiredError()
        sendErrProd(error, res)

    }
}
// duplicate error