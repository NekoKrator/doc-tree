const bcrypt = require('bcryptjs')
const { validationResult } = require('express-validator')
const User = require('../models/User')
const {
    generateAccessToken,
    generateRefreshToken,
    verifyRefreshToken,
    verifyAccessToken,
} = require('../utils/tokenUtils')

const register = async (req, res, next) => {
    try {
        const errors = validationResult(req)
        if (!errors.isEmpty()) {
            const error = new Error('Validation failed')
            error.statusCode = 400
            error.errors = errors.array()
            throw error
        }

        const { username, email, password } = req.body

        const existingUser = await User.findOne({
            $or: [{ email }, { username }],
        }).select('+refreshToken')

        if (existingUser) {
            const field = existingUser.email === email ? 'email' : 'username'
            const error = new Error(`${field} is already taken`)
            error.statusCode = 409
            throw error
        }

        const hashedPassword = await bcrypt.hash(password, 10)
        const newUser = new User({
            username,
            email,
            password: hashedPassword,
        })

        await newUser.save()

        const accessToken = generateAccessToken(newUser._id)
        const refreshToken = generateRefreshToken(newUser._id)

        newUser.refreshToken = await bcrypt.hash(refreshToken, 10)
        newUser.refreshTokenExp = Date.now() + 7 * 24 * 60 * 60 * 1000
        await newUser.save()

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
            success: true,
            user: {
                _id: newUser._id,
                username: newUser.username,
                email: newUser.email,
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
            const error = new Error('Validation failed')
            error.statusCode = 400
            error.errors = errors.array()
            throw error
        }

        const { email, password } = req.body

        const user = await User.findOne({ email }).select(
            '+password +refreshToken +refreshTokenExp'
        )

        if (!user) {
            const error = new Error('Invalid credentials')
            error.statusCode = 401
            throw error
        }

        const isMatch = await bcrypt.compare(password, user.password)

        if (!isMatch) {
            const error = new Error('Invalid credentials')
            error.statusCode = 401
            throw error
        }

        const accessToken = generateAccessToken(user._id)
        const refreshToken = generateRefreshToken(user._id)

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
            success: true,
            user: {
                _id: user._id,
                username: user.username,
                email: user.email,
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
            const error = new Error('Authorization required')
            error.statusCode = 401
            throw error
        }

        const decoded = verifyRefreshToken(refreshToken)
        const user = await User.findById(decoded.userId).select(
            '+refreshToken +refreshTokenExp'
        )

        if (
            !user ||
            !user.refreshTokenExp ||
            Date.now() > user.refreshTokenExp
        ) {
            const error = new Error('Invalid token')
            error.statusCode = 401
            throw error
        }

        const isTokenValid = await bcrypt.compare(
            refreshToken,
            user.refreshToken
        )
        if (!isTokenValid) {
            return res.status(401).json({
                success: false,
                error: 'Invalid token',
            })
        }

        const newAccessToken = generateAccessToken(user._id)
        const newRefreshToken = generateRefreshToken(user._id)

        user.refreshToken = await bcrypt.hash(newRefreshToken, 10)
        user.refreshTokenExp = Date.now() + 7 * 24 * 60 * 60 * 1000
        await user.save()

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

        res.json({ success: true })
    } catch (err) {
        next(err)
    }
}

const logout = async (req, res, next) => {
    try {
        const user = await User.findById(req.user._id)

        user.refreshToken = undefined
        user.refreshTokenExp = undefined
        await user.save()

        res.clearCookie('accessToken')
        res.clearCookie('refreshToken')

        res.json({ success: true })
    } catch (err) {
        next(err)
    }
}

const me = async (req, res, next) => {
    try {
        const { accessToken } = req.cookies
        if (!accessToken) {
            const error = new Error('Authorization required')
            error.statusCode = 401
            throw error
        }

        const decoded = verifyAccessToken(accessToken)
        const user = await User.findById(decoded.userId).select(
            '-password -refreshToken'
        )

        if (!user) {
            const error = new Error('User not found')
            error.statusCode = 404
            throw error
        }

        res.json({ success: true, user })
    } catch (err) {
        next(err)
    }
}

module.exports = { register, login, refresh, logout, me }
