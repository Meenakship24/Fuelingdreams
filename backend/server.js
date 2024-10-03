require('dotenv').config(); // Load environment variables
const express = require('express');
const bodyParser = require('body-parser');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const cors = require('cors')

const app = express();
const PORT = process.env.PORT;  // Use port from .env

// Middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cors())

// MySQL Connection Pool using .env variables
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME
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

// API endpoint to fetch profile data
app.get('/api/profile/', (req, res) => {
  //const userId = req.params.id;  // This is still being retrieved, but not used for the query
  const query = 'SELECT  f_name, l_name, email,  dob, gender, phone_no, country, address FROM user_regis WHERE id = 1';  // Hardcoded ID

  connection.query(query, (err, results) => {
    if (err) {
      console.error('Database query error:', err);  // Logging error for debugging
      res.status(500).send('Server error');
    } else if (results.length > 0) {
      console.log('Query Results:', results);  // Print the result to the console
      res.json(results[0]);
    } else {
      res.status(404).send('User not found');
    }
  });
});

// Start the server
const port = 5000;
app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});


