const express = require('express')
const jwt = require('jsonwebtoken')
const router = express.Router()
const bcrypt = require('bcrypt')
const User = require('../models/user')
const saltRounds = 12

// Sign-up route
router.post('/sign-up', async (req, res) => {
  try {
    const { username, password } = req.body

    const existingUser = await User.findOne({ username })
    if (existingUser) {
      return res.status(409).json({ err: 'Username already exists' })
    }

    const hashedPassword = bcrypt.hashSync(password, saltRounds)

    const newUser = await User.create({ username, password: hashedPassword }) // ← هنا الاسم "password"

    const payload = {
      username: newUser.username,
      _id: newUser._id,
    }

    const token = jwt.sign(payload, process.env.JWT_SECRET)

    res.status(201).json({ token })
  } catch (err) {
    res.status(400).json({ err: 'Invalid, Please try again.' })
  }
})

// Sign-in route
router.post('/sign-in', async (req, res) => {
  try {
    const user = await User.findOne({ username: req.body.username })
    if (!user) {
      return res.status(401).json({ err: 'Invalid credentials.' })
    }

    const isPasswordCorrect = bcrypt.compareSync(req.body.password, user.password) // ← هنا أيضاً
    if (!isPasswordCorrect) {
      return res.status(401).json({ err: 'Invalid credentials.' })
    }

    const payload = {
      username: user.username,
      _id: user._id,
    }

    const token = jwt.sign(payload, process.env.JWT_SECRET)

    res.status(200).json({ token }) 
  } catch (err) {
    res.status(500).json({ err: err.message })
  }
})

module.exports = router
