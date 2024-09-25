const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');

const app = express();
app.use(cors());

// Create a connection to the database
const connection = mysql.createConnection({
  host: 'Addy',
  user: 'portal',
  password: 'adnan@123',
  database: 'portal'
});



// Connect to the database
connection.connect(err => {
  if (err) {
    console.error('Error connecting to MySQL:', err.stack);
    return;
  }
  console.log('Connected to MySQL');
});

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


