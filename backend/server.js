require('dotenv').config(); // Load environment variables
const express = require('express');
const bodyParser = require('body-parser');
const mysql = require('mysql2/promise');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const moment = require('moment');
const fs = require('fs');
const path = require('path');
const cors = require('cors');

const app = express();
const port = process.env.PORT || 3000; // Use port from .env or default to 3000

// Middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cors());

// MySQL Connection Pool using .env variables
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});

// Check MySQL Connection
(async () => {
  try {
    const connection = await pool.getConnection();
    console.log('Connected to MySQL database.');
    connection.release(); // Release the connection back to the pool
  } catch (error) {
    console.error('Database connection failed:', error);
  }
})();

// Nodemailer configuration
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

// JWT secret key
const secretKey = process.env.JWT_SECRET;

// Store reset codes temporarily
let resetCodes = {};

// JWT verification middleware
const verifyToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader) {
    return res.status(403).json({ error: 'No token provided' });
  }
  const token = authHeader.split(' ')[1];
  jwt.verify(token, secretKey, (err, decoded) => {
    if (err) {
      return res.status(401).json({ error: 'Unauthorized' });
    }
    req.userId = decoded.id;
    next();
  });
};

// Check User Inactivity Middleware
const checkUserInactivity = async (req, res, next) => {
  try {
    const query = `
      UPDATE user_regis 
      SET status = 0 
      WHERE last_active < ? AND status = 1
    `;
    const ninetyDaysAgo = moment().subtract(90, 'days').format('YYYY-MM-DD HH:mm:ss');
    const connection = await pool.getConnection();
    await connection.query(query, [ninetyDaysAgo]);
    connection.release(); 
    next();
  } catch (error) {
    console.error('Error checking user inactivity:', error);
    next(error);
  }
};

// Apply inactivity middleware
app.use(checkUserInactivity);

// Registration Route
app.post('/register', async (req, res) => {
  const { f_name, l_name, email, phone_no, dob, gender, country, address, password } = req.body;
  try {
    const connection = await pool.getConnection();
    await connection.beginTransaction();
    try {
      const [existingUsers] = await connection.query(
        'SELECT email, phone_no FROM user_regis WHERE email = ? OR phone_no = ?',
        [email, phone_no]
      );

      if (existingUsers.length > 0) {
        const existingUser = existingUsers[0];
        if (existingUser.email === email) {
          await connection.rollback();
          return res.status(400).json({ error: 'Email already exists' });
        }
        if (existingUser.phone_no === phone_no) {
          await connection.rollback();
          return res.status(400).json({ error: 'Phone number already exists' });
        }
      }

      const hashedPassword = await bcrypt.hash(password, 10);
      const user = { f_name, l_name, email, phone_no, dob, gender, country, address, pass: hashedPassword };
      await connection.query('INSERT INTO user_regis SET ?', user);
      await connection.commit();

      res.status(201).json({ message: 'User registered successfully. Please login.', redirect: '/portfolio-website/home' });
    } catch (error) {
      await connection.rollback();
      console.error('Error in registration:', error);
      res.status(500).json({ error: 'Error registering user' });
    } finally {
      connection.release();
    }
  } catch (error) {
    console.error('Error getting database connection:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Login Route
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const [users] = await pool.query('SELECT * FROM user_regis WHERE email = ?', [email]);
    if (users.length === 0) {
      console.log(`Login attempt failed for email: ${email}`);
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const user = users[0];
    console.log(user);
    console.log("Passwprd is:",password);
    console.log("From user input is:",user.pass);
    const isMatch = await bcrypt.compare(password, user.pass);
    console.log(isMatch);
    if (!isMatch) {
      console.log(`Password mismatch for email: ${email}`);
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    // if (password === user.pass) {
    //   console.log(`Password mismatch for email: ${email}`);
    //   return res.status(401).json({ error: 'Invalid credentials' });
    // }

    if (user.status === 1) {
      const token = jwt.sign({ id: user.id }, secretKey, { expiresIn: '1h' });
      await pool.query('UPDATE user_regis SET last_active = NOW() WHERE id = ?', [user.id]);
      return res.json({ token, redirect: '/portfolio-website/home' });
    } else if (user.status === -1) {
      return res.status(403).json({ error: 'Account has been deleted' });
    } else if (user.status === 0) {
      return res.json({ error: 'Account is deactivated', redirect: '/reactivate.html' });
    }
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Database error' });
  }
});

// Reactivate Route
app.post('/reactivate', async (req, res) => {
  const { email, pass } = req.body;
  try {
    const [users] = await pool.query('SELECT * FROM user_regis WHERE email = ?', [email]);
    if (users.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const user = users[0];
    const isMatch = await bcrypt.compare(pass, user.pass);
    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    if (user.status !== 0) {
      return res.status(400).json({ error: 'Account is not deactivated' });
    }

    const verificationCode = crypto.randomBytes(3).toString('hex');
    resetCodes[email] = verificationCode;

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Account Reactivation Verification Code',
      text: `Your account reactivation verification code is: ${verificationCode}`,
    };
    await transporter.sendMail(mailOptions);
    res.json({ message: 'Verification code sent to email' });
  } catch (error) {
    console.error('Error in reactivation:', error);
    res.status(500).json({ error: 'Error processing reactivation request' });
  }
});

// Verify Reactivation Code Route
app.post('/verify-reactivation', async (req, res) => {
  const { email, code } = req.body;
  if (resetCodes[email] === code) {
    try {
      await pool.query('UPDATE user_regis SET status = 1, last_active = NOW() WHERE email = ?', [email]);
      delete resetCodes[email];
      res.json({ message: 'Account reactivated successfully', redirect: '/login.html' });
    } catch (error) {
      console.error('Error updating user status:', error);
      res.status(500).json({ error: 'Error updating user status' });
    }
  } else {
    res.status(400).json({ error: 'Invalid or expired verification code' });
  }
});

// Start the server
app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});