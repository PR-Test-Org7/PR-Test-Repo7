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
  const query = `SELECT * FROM users WHERE username = '${username}'`;
  db.query(query, (err, results) => {
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

// ----------------------------------------------------------------
// PROTOTYPE POLLUTION via lodash merge (SAST Vulnerability #7)
// ----------------------------------------------------------------
app.post('/merge', (req, res) => {
  const userInput = req.body;
  const config = {};
  // Merging untrusted user input — Prototype Pollution via lodash merge
  _.merge(config, userInput);
  res.json({ config });
});

// ----------------------------------------------------------------
// HARDCODED JWT SECRET + NO EXPIRY (SAST Vulnerability #8)
// ----------------------------------------------------------------
const jwt = require('jsonwebtoken');
const JWT_SECRET = 'mysecretkey123'; // hardcoded, weak secret

app.post('/login', (req, res) => {
  const { username } = req.body;
  // No expiry, hardcoded secret — broken authentication
  const token = jwt.sign({ username, role: 'admin' }, JWT_SECRET);
  res.json({ token });
});

app.get('/profile', (req, res) => {
  const token = req.headers['authorization'];
  // No algorithm validation — algorithm confusion attack possible
  const decoded = jwt.verify(token, JWT_SECRET);
  res.json(decoded);
});

// ----------------------------------------------------------------
// INSECURE DIRECT OBJECT REFERENCE — IDOR (SAST Vulnerability #9)
// ----------------------------------------------------------------
app.get('/invoice', (req, res) => {
  const invoiceId = req.query.id;
  // No ownership/authorization check — any user can access any invoice
  const query = `SELECT * FROM invoices WHERE id = '${invoiceId}'`;
  db.query(query, (err, results) => {
    if (err) return res.status(500).send(err.message);
    res.json(results);
  });
});

// ----------------------------------------------------------------
// OPEN REDIRECT (SAST Vulnerability #10)
// ----------------------------------------------------------------
app.get('/redirect', (req, res) => {
  const target = req.query.url;
  // No whitelist validation — Open Redirect to arbitrary external URL
  res.redirect(target);
});

// ----------------------------------------------------------------
// ReDoS — catastrophic backtracking regex (SAST Vulnerability #11)
// ----------------------------------------------------------------
app.post('/validate-email', (req, res) => {
  const email = req.body.email;
  // Catastrophic backtracking on malicious input — ReDoS
  const vulnerable = /^([a-zA-Z0-9]+)+@[a-zA-Z0-9]+\.[a-zA-Z]{2,}$/.test(email);
  res.json({ valid: vulnerable });
});

// ----------------------------------------------------------------
// SENSITIVE DATA LOGGED TO CONSOLE (SAST Vulnerability #12)
// ----------------------------------------------------------------
app.post('/payment', (req, res) => {
  const { cardNumber, cvv, amount } = req.body;
  // Logging PII and sensitive financial data
  console.log(`Processing payment: card=${cardNumber} cvv=${cvv} amount=${amount}`);
  res.json({ status: 'processed' });
});

app.listen(3000, () => {
  console.log('Server running on port 3000');
});

