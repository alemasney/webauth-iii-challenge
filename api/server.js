const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const secrets = require('../config/secrets.js')
const restricted = require('./restricted-middleware.js');

const server = express();

server.use(helmet());
server.use(express.json());
server.use(cors());

const Users = require('./model.js');

server.post('/api/register', (req, res) => {
    let user = req.body;
    const hash = bcrypt.hashSync(user.password, 10); // 2 ^ n
    user.password = hash;

    Users.add(user)
        .then(saved => {
            res.status(201).json(saved);
        })
        .catch(error => {
            res.status(500).json(error);
        });
});

server.post('/api/login', (req, res) => {
    let { username, password } = req.body;
    
    Users.findBy({ username })
        .first()
        .then(user => {
            if (user && bcrypt.compareSync(password, user.password)) {
                console.log(password)
                console.log(user.password)
                const token = genToken(user)

                res.status(200).json({

                    message: `Welcome ${user.username}!`,
                    token

                });
            } else {
                res.status(401).json({ message: 'Invalid Credentials' });
            }
        })
        .catch(error => {
            res.status(500).json(error);
        });
});

server.get('/api/users', restricted, (req, res) => {
    Users.find()
        .then(users => {
            res.json(users);
        })
        .catch(err => res.send(err));
});

function genToken(user) {

    const payload = {
        subject: "user",
        username: user.username,
    };

    const secret = secrets.jwtSecret;

    const options = {
        expiresIn: '1h'
    };

    return token = jwt.sign(payload, secret, options);

}

module.exports = server;