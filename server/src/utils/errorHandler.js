const errorHandler = (err, req, res, next) => {
    console.log(`[${new Date().toISOString()}] Error: ${err.stack}`)

    let statusCode = err.statusCode || 500
    let message = err.message || 'Internal Server Error'

    switch (err.name) {
        case 'ValidationError':
            statusCode = 400
            message = Object.values(err.errors).map((e) => e.message)
            break
        case 'JsonWebTokenError':
            statusCode = 401
            message = 'Invalid token'
            break
        case 'TokenExpiredError':
            statusCode = 401
            message = 'Token expired'
            break
        case 'MongoServerError':
            if (err.code === 11000) {
                statusCode = 409
                message = `Duplicate field value: ${Object.keys(
                    err.keyPattern
                )}`
            }
            break
    }

    res.status(statusCode).json({
        success: false,
        error: message,
    })
}

module.exports = errorHandler
