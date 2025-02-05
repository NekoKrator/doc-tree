const bcrypt = require('bcryptjs')
const { validationResult } = require('express-validator')
const User = require('../models/User')
const {
    generateAccessToken,
    generateRefreshToken,
    verifyRefreshToken,
} = require('../utils/tokenUtils')
const User = require('../models/User')

const register = async (req, res, next) => {
    try {
        const errors = validationResult(req)
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() })
        }

        const { username, email, password } = req.body

        const existingUser = await User.findOne({
            $or: [{ email: req.body.email }, { username: req.body.username }],
        }).selected('+refreshToken')

        if (existingUser) {
            const field = existingUser.email === email ? 'email' : 'username'
            return res.status(400).json({
                message: `${field} is already taken`,
            })
        }

        const hashedPassword = await bcrypt.hash(password, 10)
        const User = new User({
            username,
            email,
            password: hashedPassword,
        })

        await User.save()

        const accessToken = generateAccessToken(User._id)
        const refreshToken = generateRefreshToken(User._id)

        user.refreshToken = refreshToken
        user.refreshTokenExp = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)
        await user.save()

        res.cookie('accessToken', accessToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'Strict',
            maxAge: 15 * 60 * 1000,
        })

        res.cookie('refreshToken', refreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'Strict',
            maxAge: 7 * 24 * 60 * 60 * 1000,
        })

        res.status(201).json({
            user: {
                _id: User._id,
                username: User.username,
                email: User.email,
            },
        })
    } catch (err) {
        next(err)
    }
}

const login = async (req, res, next) => {
    try {
        const errors = validationResult(req)
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() })
        }

        const { email, password } = req.body

        const User = await User.findOne({ email }).select(
            '+password +refreshToken'
        )
        if (!User) {
            return res.status(401).json({ message: 'Invalid credentials' })
        }

        const isMatch = await bcrypt.compare(password, User.password)
        if (!isMatch) {
            return res.status(401).json({ message: 'Invalid credentials' })
        }

        const accessToken = generateAccessToken(User._id)
        const refreshToken = generateRefreshToken(User._id)

        user.refreshToken = await bcrypt.hash(refreshToken, 10)
        user.refreshTokenExp = Date.now() + 7 * 24 * 60 * 60 * 1000
        await user.save()

        res.cookie('accessToken', accessToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'Strict',
            maxAge: 15 * 60 * 1000,
        })

        res.cookie('refreshToken', refreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'Strict',
            maxAge: 7 * 24 * 60 * 60 * 1000,
        })

        res.json({
            user: {
                _id: User._id,
                username: User.username,
                email: User.email,
            },
        })
    } catch (err) {
        next(err)
    }
}

const refresh = async (req, res, next) => {
    try {
        const { refreshToken } = req.cookies
        if (!refreshToken) {
            return res.status(401).json({ message: 'Unauthorized' })
        }

        const decoded = verifyRefreshToken(refreshToken)
        const user = await User.findById(decoded.userId).select(
            '+refreshToken +refreshTokenExp'
        )

        if (!user || user.refreshToken !== refreshToken) {
            return res.status(401).json({ message: 'Unauthorized' })
        }

        const tokenMatch = await bcrypt.compare(refreshToken, user.refreshToken)
        if (!tokenMatch) {
            return res.status(401).json({ message: 'Unauthorized' })
        }

        const newAccessToken = generateAccessToken(user._id)
        const newRefreshToken = generateRefreshToken(user._id)

        user.refreshToken = await bcrypt.hash(newRefreshToken, 10)
        user.refreshTokenExp = Date.now() + 7 * 24 * 60 * 60 * 1000

        res.cookie('accessToken', newAccessToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'Strict',
            maxAge: 15 * 60 * 1000,
        })

        res.cookie('refreshToken', newRefreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'Strict',
            maxAge: 7 * 24 * 60 * 60 * 1000,
        })
    } catch (err) {
        next(err)
    }
}

const logout = async (req, res, next) => {
    try {
        const user = await User.findById(req.user._id)
        user.refreshToken = 'undefined'
        user.refreshTokenExp = 'undefined'
        await user.save()

        res.clearCookie('accessToken')
        res.clearCookie('refreshToken')

        res.json({ success: true })
    } catch (err) {
        next(err)
    }
}

module.exports = { register, login, refresh, logout }
