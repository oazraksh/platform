const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const nodemailer = require('nodemailer');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

// Database connection
const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'Ah128256', // پسورد MySQL
  database: 'platform'
});

db.connect(err => {
  if (err) {
    console.error('Error connecting to MySQL:', err);
    return;
  }
  console.log('Connected to MySQL successfully!');
});

// Nodemailer transporter (Gmail)
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// تابع تولید OTP امن (۸ کاراکتری ترکیبی)
function generateOTP(length = 8) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let otp = '';
  for (let i = 0; i < length; i++) {
    otp += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return otp;
}

function sendOTP(email, otp) {
  const mailOptions = {
    from: process.env.EMAIL_USER,
    to: email,
    subject: 'Your OTP Code',
    text: `Your verification code is: ${otp}`
  };
  return transporter.sendMail(mailOptions);
}

// Register with OTP
app.post('/adduser', async (req, res) => {
  const { username, email, password } = req.body;

  // اعتبارسنجی ایمیل و پسورد
  if (!email.includes('@')) {
    return res.status(400).json({ message: 'Invalid email format' });
  }
  if (!password || password.length < 8) {
    return res.status(400).json({ message: 'Password must be at least 8 characters long' });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  const otp = generateOTP(8);
  const hashedOtp = await bcrypt.hash(otp, 10);

  const sql = 'INSERT INTO users (username, email, password, otp, verified) VALUES (?, ?, ?, ?, ?)';
  db.query(sql, [username, email, hashedPassword, hashedOtp, false], async (err, result) => {
    if (err) {
      console.error(err);
      res.status(500).json({ message: 'Error adding user' });
      return;
    }

    await sendOTP(email, otp);
    res.json({ message: 'User registered. Please verify OTP sent to your email.' });
  });
});

// Verify OTP
app.post('/verify', (req, res) => {
  const { email, otp } = req.body;
  const sql = 'SELECT * FROM users WHERE email = ?';
  db.query(sql, [email], async (err, results) => {
    if (err) return res.status(500).send(err);
    if (results.length > 0) {
      const user = results[0];
      const match = await bcrypt.compare(otp, user.otp);
      if (match) {
        const updateSql = 'UPDATE users SET verified = true, otp = NULL WHERE email = ?';
        db.query(updateSql, [email], (err2) => {
          if (err2) return res.status(500).send(err2);
          res.json({ message: 'Account verified successfully!' });
        });
      } else {
        res.status(400).json({ message: 'Invalid OTP' });
      }
    } else {
      res.status(400).json({ message: 'User not found' });
    }
  });
});

// Login
app.post('/login', (req, res) => {
  const { email, password } = req.body;
  const sql = 'SELECT * FROM users WHERE email = ? AND verified = true';
  db.query(sql, [email], async (err, results) => {
    if (err) {
      res.status(500).send(err);
      return;
    }
    if (results.length > 0) {
      const user = results[0];
      const match = await bcrypt.compare(password, user.password);
      if (match) {
        const token = jwt.sign(
          { id: user.id, email: user.email },
          process.env.JWT_SECRET,
          { expiresIn: '1h' }
        );
        res.json({ message: 'Login successful!', token });
      } else {
        res.status(401).json({ message: 'Invalid credentials' });
      }
    } else {
      res.status(401).json({ message: 'Invalid credentials or account not verified' });
    }
  });
});

// Middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'Token required' });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'Invalid token' });
    req.user = user;
    next();
  });
}

// Protected route
app.get('/profile', authenticateToken, (req, res) => {
  res.json({ message: 'Welcome to your profile!', user: req.user });
});

// Start server
app.listen(3000, () => {
  console.log('Server running on port 3000');
});