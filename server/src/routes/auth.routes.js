const { Router } = require('express')
const { body } = require('express-validator')
const rateLimit = require('express-rate-limit')
const {
    register,
    login,
    refresh,
    logout,
} = require('../controllers/auth.controller')
const authLimiter = require('../middlewares/rateLimiter')

const router = Router()

const registerValidator = [
    body('username')
        .trim()
        .isLength({ min: 3 })
        .withMessage('Username must be at least 3 characters'),
    body('email')
        .trim()
        .normalizeEmail()
        .isEmail()
        .withMessage('Invalid email addres'),
    body('password')
        .isLength({ min: 8 })
        .withMessage('Password must be atleast 8 characters'),
]

const loginValidator = [
    body('email')
        .trim()
        .normalizeEmail()
        .isEmail()
        .withMessage('Invalid email addres'),
    body('password').exists().withMessage('Password is required'),
]

router.post('/register', authLimiter, registerValidator, register)
router.post('/login', authLimiter, loginValidator, login)
router.post('/refresh', refresh)
router.post('/logout', authMiddleware, logout)

module.exports = router
