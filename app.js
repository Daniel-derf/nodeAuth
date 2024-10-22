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
        password: passwordHash
    })

    try {
        await user.save()

        res.status(201).json({msg: 'Usuário criado com sucesso!'})

    } catch(error){
        res.status(500).json({msg: error})
    }
})

// login user
app.post('/auth/login', async (req, res) => {
    const {email, password} = req.body

    if (!email) {
        return res.status(422).json({msg: 'O email é obrigatório!'})
    }

    if (!password) {
        return res.status(422).json({msg: 'A password é obrigatório!'})
    }

    // check if user exists
    const user = await User.findOne({ email: email })

    if(!user){
        return res.status(404).json({msg: 'Usuário não encontrado!'})
    }

    // check if password match
    const checkPassword = await bcrypt.compare(password, user.password)

    if (!checkPassword){
        return res.status(422).json({msg: 'Senha inválida!'})
    }

    try {
        const secret = process.env.SECRET

        const token = jwt.sign({
            id: user._i,
        }, secret,)

        res.status(200).json({msg: "Autenticação realizada com sucesso", token})

    } catch(err){
        res.status(500).json({msg: err})
    }


})

// private route
app.get('/user/:id', checkToken, async (req,res) => {
    const id = req.params.id

    // excluindo a senha do usuario do retorno na busca (-password)
    const user = await User.findById(id, '-password')

    if (!user){
        return res.status(404).json({msg: 'usuario não encontrado'})
    }

    return res.status(200).json({ user })
})

function checkToken(req, res, next){
    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(' ')[1]

    if(!token){
        return res.status(401).json({msg: 'Acesso negado!'})
    }

    try {
        const secret = process.env.SECRET

        jwt.verify(token, secret)

        next()
        
    } catch(error){
        res.status(400).json({msg: 'token inválido'})
    }
    
}

const dbUser = process.env.DB_USER
const dbPassword = process.env.DB_PASS

mongoose.connect(`mongodb+srv://${dbUser}:${dbPassword}@authjwtyoutube.rmuxv.mongodb.net/?retryWrites=true&w=majority&appName=AuthJwtYoutube`).then(() => {
    app.listen(3001)
    console.log('Conectou ao banco!')
}).catch((err) => console.log(err))

app.listen(3000)