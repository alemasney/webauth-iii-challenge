const jwt = require('jsonwebtoken');
const secrets = require('../config/secrets.js');

const Users = require('./model.js');

module.exports = (req, res, next) => {

    const token = req.headers.authorization

    if (token) {
        jwt.verify(token, secrets.jwtSecret, (err, decodedToken) => {
            if (err) {
                res.status(401).json({ message: 'please provide valid credentials' });
            } else { 
                req.decodedJwt = decodedToken;
                next();
            }
        })
    } else {
        res.status(500).json({ message: 'Could not verify account' })
    }
}