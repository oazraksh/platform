// server.js

require('dotenv').config();

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const mysql = require('mysql2/promise');
const nodemailer = require('nodemailer');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
const rateLimit = require('express-rate-limit');
const morgan = require('morgan');
const winston = require('winston');

// ----- Environment Variables with Fallbacks -----
const {
  PORT = 3000,
  DB_HOST = 'localhost',
  DB_USER = 'root',
  DB_PASS = '',
  DB_NAME = 'social_media',
  EMAIL_USER,
  EMAIL_PASS,
  JWT_SECRET = 'supersecretkey',
  NODE_ENV = 'development'
} = process.env;

// ----- Logging Setup -----
const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [new winston.transports.Console()]
});

// ----- Express App Setup -----
const app = express();
app.use(helmet());
app.use(cors());
app.use(express.json());
app.use(morgan('combined', {
  stream: { write: message => logger.info(message.trim()) }
}));

// ----- MySQL Connection Pool -----
const pool = mysql.createPool({
  host: DB_HOST,
  user: DB_USER,
  password: DB_PASS,
  database: DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// ----- Nodemailer Transport -----
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: EMAIL_USER,
    pass: EMAIL_PASS
  }
});

// ----- Utility Functions -----
function generateOTP(length = 6) {
  // Generates a secure random numeric OTP
  const min = 10 ** (length - 1);
  const max = 10 ** length - 1;
  return (Math.floor(Math.random() * (max - min + 1)) + min).toString();
}

async function sendOTPEmail(email, otp) {
  const mailOptions = {
    from: `"Social Media App" <${EMAIL_USER}>`,
    to: email,
    subject: 'Your OTP Code',
    text: `Your OTP code is ${otp}. It will expire in 10 minutes.`
  };
  await transporter.sendMail(mailOptions);
}

// ----- Rate Limiting -----
const otpLimiter = rateLimit({
  windowMs: 10 * 60 * 1000, // 10 minutes
  max: 5,
  message: 'Too many OTP requests, please try again later.'
});
const verifyLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 5,
  message: 'Too many verification attempts, please try again later.'
});
const loginLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 10,
  message: 'Too many login attempts, please try again later.'
});

// ----- JWT Authentication Middleware -----
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'Token missing' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'Invalid or expired token' });
    req.user = user;
    next();
  });
}

// ----- Routes -----

// Root Health Check
app.get('/', (req, res) => {
  res.json({ status: 'ok', message: 'Social Media API is running' });
});

// User Registration with OTP
app.post('/adduser', otpLimiter, [
  body('email').isEmail().normalizeEmail(),
  body('password').isLength({ min: 8 })
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty())
      return res.status(400).json({ errors: errors.array() });

    const { email, password } = req.body;
    const [existing] = await pool.query('SELECT id FROM users WHERE email = ?', [email]);
    if (existing.length > 0)
      return res.status(409).json({ message: 'User already exists' });

    const hashedPassword = await bcrypt.hash(password, 10);
    const otp = generateOTP();
    const hashedOTP = await bcrypt.hash(otp, 10);
    const otpExpires = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

    await pool.query(
      'INSERT INTO users (email, password, otp_hash, otp_expires, is_verified, created_at) VALUES (?, ?, ?, ?, 0, NOW())',
      [email, hashedPassword, hashedOTP, otpExpires]
    );

    await sendOTPEmail(email, otp);
    res.status(201).json({ message: 'Registration successful. Please verify your email using the OTP sent.' });
  } catch (err) {
    logger.error('Error in /adduser:', err);
    res.status(500).json({ message: 'Registration failed.' });
  }
});

// OTP Verification
app.post('/verify', verifyLimiter, [
  body('email').isEmail().normalizeEmail(),
  body('otp').isLength({ min: 6, max: 6 })
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty())
      return res.status(400).json({ errors: errors.array() });

    const { email, otp } = req.body;
    const [users] = await pool.query('SELECT id, otp_hash, otp_expires, is_verified FROM users WHERE email = ?', [email]);
    if (users.length === 0)
      return res.status(404).json({ message: 'User not found' });

    const user = users[0];
    if (user.is_verified)
      return res.status(400).json({ message: 'User already verified' });

    if (!user.otp_hash || !user.otp_expires)
      return res.status(400).json({ message: 'No OTP pending verification' });

    if (new Date() > user.otp_expires)
      return res.status(400).json({ message: 'OTP expired' });

    const match = await bcrypt.compare(otp, user.otp_hash);
    if (!match)
      return res.status(400).json({ message: 'Invalid OTP' });

    await pool.query(
      'UPDATE users SET is_verified = 1, otp_hash = NULL, otp_expires = NULL WHERE id = ?',
      [user.id]
    );
    res.json({ message: 'Email verified successfully' });
  } catch (err) {
    logger.error('Error in /verify:', err);
    res.status(500).json({ message: 'Verification failed.' });
  }
});

// Login and JWT Issuance
app.post('/login', loginLimiter, [
  body('email').isEmail().normalizeEmail(),
  body('password').isLength({ min: 8 })
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty())
      return res.status(400).json({ errors: errors.array() });

    const { email, password } = req.body;
    const [users] = await pool.query('SELECT id, password, is_verified FROM users WHERE email = ?', [email]);
    if (users.length === 0)
      return res.status(401).json({ message: 'Invalid credentials' });

    const user = users[0];
    if (!user.is_verified)
      return res.status(403).json({ message: 'Email not verified' });

    const match = await bcrypt.compare(password, user.password);
    if (!match)
      return res.status(401).json({ message: 'Invalid credentials' });

    const token = jwt.sign(
      { id: user.id, email },
      JWT_SECRET,
      { expiresIn: '1h' }
    );
    res.json({ token });
  } catch (err) {
    logger.error('Error in /login:', err);
    res.status(500).json({ message: 'Login failed.' });
  }
});

// Protected Profile Route
app.get('/profile', authenticateToken, async (req, res) => {
  try {
    const [users] = await pool.query('SELECT id, email, is_verified, created_at FROM users WHERE id = ?', [req.user.id]);
    if (users.length === 0)
      return res.status(404).json({ message: 'User not found' });

    const user = users[0];
    res.json({
      id: user.id,
      email: user.email,
      is_verified: !!user.is_verified,
      created_at: user.created_at
    });
  } catch (err) {
    logger.error('Error in /profile:', err);
    res.status(500).json({ message: 'Failed to fetch profile.' });
  }
});

// Optional: List All Users (Testing Only)
app.get('/users', async (req, res) => {
  try {
    const [users] = await pool.query('SELECT id, email, is_verified, created_at FROM users');
    res.json(users);
  } catch (err) {
    logger.error('Error in /users:', err);
    res.status(500).json({ message: 'Failed to fetch users.' });
  }
});

// ----- Centralized Error Handler -----
app.use((err, req, res, next) => {
  logger.error('Unhandled error:', err);
  res.status(500).json({ message: 'Internal server error.' });
});

// ----- Graceful Shutdown -----
const server = app.listen(PORT, () => {
  logger.info(`Server running on port ${PORT} (${NODE_ENV})`);
});

process.on('SIGTERM', async () => {
  logger.info('SIGTERM received, shutting down gracefully');
  server.close(async () => {
    await pool.end();
    logger.info('Server and DB connections closed');
    process.exit(0);
  });
});

process.on('SIGINT', async () => {
  logger.info('SIGINT received, shutting down gracefully');
  server.close(async () => {
    await pool.end();
    logger.info('Server and DB connections closed');
    process.exit(0);
  });
});