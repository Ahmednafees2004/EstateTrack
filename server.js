const express = require('express');
const crypto = require('crypto');
const mysql = require('mysql2');
const session = require('express-session');
const app = express();

app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

// Configure server-side sessions. Only the session ID is stored in the browser cookie.
app.use(session({
  secret: process.env.SESSION_SECRET || 'replace-this-development-secret',
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 60 * 60 * 1000, // Keep the user logged in for one hour.
    httpOnly: true, // Prevent browser JavaScript from reading the session cookie.
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production' // Production must use HTTPS.
  }
}));

const conn = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: process.env.ROOTPASS,
  database: process.env.DB_NAME || 'estatetrack',
  port: 3306
});

conn.connect(err => {
  if (err) console.error('Could not connect to MySQL:', err);
  else console.log('Database connection established');
});

const hashPassword = (password, salt) => crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
const escapeHtml = value => String(value).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

app.post('/register', (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !email || !password) return res.status(400).send('All fields are required. <a href="register.html">Try again</a>');
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = hashPassword(password, salt);
  conn.query('INSERT INTO users (username, email, password, salt) VALUES (?, ?, ?, ?)',
    [username, email, hash, salt], err => {
      if (err) {
        if (err.code === 'ER_DUP_ENTRY') return res.status(409).send('Username or email already exists. <a href="register.html">Try again</a>');
        console.error(err);
        return res.status(500).send('Registration failed. <a href="register.html">Try again</a>');
      }
      res.send('You have successfully registered. <a href="login.html">Login here</a>');
    });
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(401).send('The login credentials were incorrect. <a href="login.html">Try again</a>');
  conn.query('SELECT password, salt FROM users WHERE username = ?', [username], (err, rows) => {
    if (err) {
      console.error(err);
      return res.status(500).send('Login unavailable. <a href="login.html">Try again</a>');
    }
    if (!rows.length) return res.status(401).send('The login credentials were incorrect. <a href="login.html">Try again</a>');
    const candidate = Buffer.from(hashPassword(password, rows[0].salt), 'hex');
    const stored = Buffer.from(rows[0].password, 'hex');
    if (candidate.length !== stored.length || !crypto.timingSafeEqual(candidate, stored)) {
      return res.status(401).send('The login credentials were incorrect. <a href="login.html">Try again</a>');
    }
    // Store the username after authentication so it is available on other routes.
    req.session.username = username;
    req.session.save(saveErr => {
      if (saveErr) {
        console.error(saveErr);
        return res.status(500).send('Could not start your session. <a href="login.html">Try again</a>');
      }
      res.send(`You have logged in successfully, ${escapeHtml(username)}. <a href="/profile">View your profile</a>`);
    });
  });
});

// Display a second page that reads the username stored in the login session.
app.get('/profile', (req, res) => {
  if (!req.session.username) {
    return res.status(401).send('You are not logged in. <a href="/login.html">Login here</a>');
  }

  res.send(`
    <h1>EstateTrack Profile</h1>
    <p>Welcome, ${escapeHtml(req.session.username)}!</p>
    <p><a href="/logout">Log out</a></p>
  `);
});

// Destroy all session data and remove the session cookie when the user logs out.
app.get('/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) {
      console.error(err);
      return res.status(500).send('There was an error logging out. <a href="/profile">Try again</a>');
    }

    res.clearCookie('connect.sid');
    res.send('You have been logged out successfully. <a href="/login.html">Login again</a>');
  });
});

app.listen(3000, () => console.log('Server running at http://localhost:3000/register.html'));
