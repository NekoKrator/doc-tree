const errorHandler = (err, req, res, next) => {
    console.log(`[${new Date().toISOString()}] Error: ${err.stack}`)

    let statusCode = err.statusCode || 500
    let message = err.message || 'Internal Server Error'
    let details = null

    if (err.errors?.length) {
        statusCode = 400
        message = 'Validation error'
        details = err.errors.map((e) => e.msg || e.message)
    }

    switch (err.name) {
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

    if (err.statusCode === 409 && !err.name) {
        message = err.message
    }

    const response = { success: false, error: message }
    if (details) response.details = details

    res.status(statusCode).json(response)
}
