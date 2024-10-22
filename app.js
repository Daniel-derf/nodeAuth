require('dotenv').config()
const express = require('express')
const mongoose = require('mongoose')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')

const app = express()

app.use(express.json())

const User = require('./models/User')

app.get('/', (req, res) => {
    res.status(200).json({'msg': 'Bem vindo a nossa API!'})
})

// Register User
app.post('/auth/register', async(req, res) => {

    const {name, email, password, confirmPassword} = req.body

    // validation
    if (!name) {
        return res.status(422).json({msg: 'O nome é obrigatório!'})
    }

    if (!email) {
        return res.status(422).json({msg: 'O email é obrigatório!'})
    }

    if (!password) {
        return res.status(422).json({msg: 'A password é obrigatório!'})
    }

    if(password !== confirmPassword) {
        return res.status(422).json({msg: 'As senhas não conferem!'})
    }

    // check if user exists
    const userExists = await User.findOne({ email: email })

    if(userExists){
        return res.status(422).json({msg: 'Por favor, utilize outro email!'})
    }

    // create password
    const salt = await bcrypt.genSalt(12)
    const passwordHash = await bcrypt.hash(password, salt)

    // create user
    const user = new User({
        name,
        email,
        password
    })

    try {
        await user.save()

        res.status(201).json({msg: 'Usuário criado com sucesso!'})

    } catch(error){
        res.status(500).json({msg: error})
    }
})

const dbUser = process.env.DB_USER
const dbPassword = process.env.DB_PASS

mongoose.connect(`mongodb+srv://${dbUser}:${dbPassword}@authjwtyoutube.rmuxv.mongodb.net/?retryWrites=true&w=majority&appName=AuthJwtYoutube`).then(() => {
    app.listen(3001)
    console.log('Conectou ao banco!')
}).catch((err) => console.log(err))

app.listen(3000)