require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const fs = require('fs');
const https = require('https');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const port = process.env.PORT || 3000;

app.use(bodyParser.json());
app.use(cors());


const secret = process.env.JWT_SECRET || 'your-secret-key';


const users = [
  { id: 1, username: 'user1', password: bcrypt.hashSync('password1', 8) },
  { id: 2, username: 'user2', password: bcrypt.hashSync('password2', 8) },
];

// Register user
app.post('/register', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).send({ message: 'Username and password are required.' });
  }
  const hashedPassword = bcrypt.hashSync(password, 8);
  users.push({ id: users.length + 1, username, password: hashedPassword });
  res.status(201).send({ message: 'User registered successfully.' });
});

// Authenticate user
app.post('/authenticate', (req, res) => {
  const { username, password } = req.body;
  const user = users.find(u => u.username === username);

  if (user && bcrypt.compareSync(password, user.password)) {
    const token = jwt.sign({ id: user.id, username: user.username }, secret, { expiresIn: '1h' });
    res.status(200).send({ token });
  } else {
    res.status(401).send({ message: 'Authentication failed.' });
  }
});

// Middleware to authenticate token
function authenticateToken(req, res, next) {
  const token = req.headers['authorization'];
  console.log('->',token)
  if (!token) return res.sendStatus(401);
  
  const bearerToken = token.split(' ')[1];
  jwt.verify(bearerToken, secret, (err, user) => {
    if (err) return res.sendStatus(403);  // Token inválido ou expirado = Forbidden
    
    console.log('->passou');
    req.user = user;
    next();
  });
}

// Protected route
app.get('/protected', authenticateToken, (req, res) => {
  res.send('This is a protected route');
});

// Server configuration
if (process.env.NODE_ENV === 'production' || process.env.USE_HTTPS === 'true') {
  // HTTPS server configuration
  let options;
  try {
    options = {
      key: fs.readFileSync(process.env.SSL_KEY_PATH),
      cert: fs.readFileSync(process.env.SSL_CERT_PATH)
    };
  } catch (error) {
    console.error('Error reading SSL files:', error);
    process.exit(1);
  }

  const httpsServer = https.createServer(options, app);

  httpsServer.listen(port, () => {
    console.log(`Server running on port ${port} with HTTPS`);
  });
} else {
  // HTTP server configuration
  app.listen(port, () => {
    console.log(`Server running on port ${port} with HTTP`);
  });
}
