const express = require('express');
const mysql = require('mysql');
const axios = require('axios');
const _ = require('lodash');
const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ----------------------------------------------------------------
// HARDCODED CREDENTIALS (SAST Vulnerability #1)
// ----------------------------------------------------------------
const DB_HOST = 'localhost';
const DB_USER = 'admin';
const DB_PASS = 'SuperSecret@123';   // hardcoded password
const API_SECRET_KEY = 'sk-prod-9f8e7d6c5b4a3210fedcba9876543210'; // hardcoded API key

const db = mysql.createConnection({
  host: DB_HOST,
  user: DB_USER,
  password: DB_PASS,
  database: 'users_db'
});

// ----------------------------------------------------------------
// SQL INJECTION (SAST Vulnerability #2)
// ----------------------------------------------------------------
app.get('/user', (req, res) => {
  const username = req.query.username;
  // Directly interpolating user input into SQL query — SQL Injection
  const query = 'SELECT * FROM users WHERE username = ?';
  db.query(query, [username], (err, results) => {
    if (err) return res.status(500).send(err.message);
    res.json(results);
  });
});

// ----------------------------------------------------------------
// REFLECTED XSS (SAST Vulnerability #3)
// ----------------------------------------------------------------
app.get('/search', (req, res) => {
  const term = req.query.q;
  // Reflecting unsanitised user input directly into HTML — XSS
  res.send(`<h1>Search Results for: ${term}</h1>`);
});

// ----------------------------------------------------------------
// COMMAND INJECTION via eval() (SAST Vulnerability #4)
// ----------------------------------------------------------------
app.post('/calculate', (req, res) => {
  const expression = req.body.expr;
  // eval() with untrusted input — Remote Code Execution / Command Injection
  const result = eval(expression);
  res.json({ result });
});

// ----------------------------------------------------------------
// PATH TRAVERSAL (SAST Vulnerability #5)
// ----------------------------------------------------------------
const fs = require('fs');
const path = require('path');

app.get('/file', (req, res) => {
  const fileName = req.query.name;
  // No path sanitisation — Path Traversal (e.g. ../../etc/passwd)
  const filePath = path.join(__dirname, 'uploads', fileName);
  fs.readFile(filePath, 'utf8', (err, data) => {
    if (err) return res.status(404).send('File not found');
    res.send(data);
  });
});

// ----------------------------------------------------------------
// INSECURE RANDOM TOKEN (SAST Vulnerability #6)
// ----------------------------------------------------------------
app.get('/token', (req, res) => {
  // Math.random() is not cryptographically secure — weak token
  const token = Math.random().toString(36).substring(2);
  res.json({ token });
});

// ----------------------------------------------------------------
// SCA: axios 1.12.2 usage — SSRF-prone external request
// ----------------------------------------------------------------
app.get('/fetch', async (req, res) => {
  const url = req.query.url;
  // axios 1.12.2 is affected by CVE-2025-27152 (credential exposure / SSRF)
  const response = await axios.get(url);
  res.send(response.data);
});

app.listen(3000, () => {
  console.log('Server running on port 3000');
});

