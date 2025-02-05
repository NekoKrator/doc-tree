require('dotenv').config()
const express = require('express')
const mongoose = require('mongoose')
const cors = require('cors')
const authRoutes = require('./routes/auth.routes')
const errorHandler = require('./utils/errorHandler')
const app = express()

app.use(
    cors({
        origin: process.env.CLIENT_URL,
        credentials: true,
    })
)

app.use(express.json())
app.use(express.urlencoded({ extended: true }))

mongoose
    .connect(process.env.MONGO_URI, {
        useNewUrlParser: true,
        useUnifiedTopology: true,
    })
    .then(() => console.log('MongoDB connected'))
    .catch((err) => console.log('MongoDB connection error:', err))

app.use('/api/auth', authRoutes)
app.use(errorHandler)

const PORT = process.env.PORT || 5000

app.listen(PORT, () => {
    console.log(
        `Server running in ${process.env.NODE_ENV} mode on port ${PORT}`
    )
})
