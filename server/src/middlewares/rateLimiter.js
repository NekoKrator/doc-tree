const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15m
    max: 5,
    message: 'Too many attemps, please try again later',
})

export default authLimiter
