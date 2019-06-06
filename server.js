const express = require('express');
const helmet = require('helmet');
cors = require('cors');
bcrypt = require('bcryptjs');

const db = require('./data/dbConfig.js');
const Users = require('./users/users-model');

const server = express();

server.use(helmet());
server.use(express.json());
server.use(cors());

//main
server.get('/', (req, res) => {
  res.send('Suh');
});

server.post('/api/register', (req, res) => {
  let user = req.body;
  //generate a hash from user's pw
  const hash = bcrypt.hashSync(user.password, 12);
  //override user.password with hash
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
        res.status(200).json({ message: `Welcome ${user.username}! You are logged in.` });
      } else {
        res.status(401).json({ message: 'You shall not pass!' });
      }
    })
    .catch(error => {
      res.status(500).json(error);
    });
});

server.post('/api/users', restricted, (req, res) => {
  Users.find()
    .then(users => {
      res.json(users);
    })
    .catch(err => res.send({ message: 'You shall not pass!' }));
});

//plugged in functions

function restricted(req, res, next) {
  const { username, password } = req.headers;

  if (username && password) {
    Users.findBy({ username })
      .first()
      .then(user => {
        if (user && bcrypt.compareSync(password, user.password)) {
          next();
        } else {
          res.status(401).json({ message: 'Invalid Credentials' });
        }
      })
      .catch(error => {
        res.status(500).json({ message: 'ran into a unexpected error' });
      });
  } else {
    res.status(400).json({ message: 'no credentials provided' });
  }
}

module.exports = server;