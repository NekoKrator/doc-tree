const mongoose = require('mongoose')

const userSchema = new mongoose.Schema(
    {
        username: {
            type: String,
            required: [true, 'Username is required'],
            unique: true,
            trim: true,
            minlength: [3, 'Username must be at least 3 characters long'],
            maxlength: [16, 'Username must be at most 16 characters long'],
        },
        email: {
            type: String,
            required: [true, 'Email is required'],
            unique: true,
            lowercase: true,
            validate: {
                validator: (v) =>
                    /^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/.test(v),
                message: 'Email is invalid',
            },
        },
        password: {
            type: String,
            required: [true, 'Password is required'],
            select: false,
            minlength: [8, 'Password must be at least 8 characters long'],
            maxlength: [128, 'Password must be at most 128 characters long'],
        },
        refreshToken: {
            type: String,
            select: false,
        },
        refreshTokenExp: {
            type: Date,
            select: false,
        },
        folders: [
            {
                type: mongoose.Schema.Types.ObjectId,
                ref: 'Folder',
            },
        ],
    },
    {
        timestamps: true,
        toJSON: {
            virtuals: true,
            transform: (doc, ret) => {
                delete ret.password
                delete ret.refreshToken
                delete ret.refreshTokenExp
                return ret
            },
        },
    }
)

module.exports = mongoose.model('User', userSchema)
