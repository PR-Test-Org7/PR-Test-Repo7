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
// CRITICAL: INSECURE DESERIALIZATION (RCE via serialize-javascript)
// ----------------------------------------------------------------
const serialize = require('serialize-javascript');

app.post('/restore-session', (req, res) => {
  // Deserializing untrusted user-supplied data — Remote Code Execution
  const sessionData = eval('(' + req.body.session + ')');
  res.json({ restored: sessionData });
});

// ----------------------------------------------------------------
// CRITICAL: XML EXTERNAL ENTITY (XXE) INJECTION
// ----------------------------------------------------------------
const libxmljs = require('libxmljs');

app.post('/parse-xml', (req, res) => {
  // noent: true enables external entity processing — XXE
  const doc = libxmljs.parseXml(req.body.xml, { noent: true, noblanks: true });
  res.send(doc.toString());
});

// ----------------------------------------------------------------
// CRITICAL: SERVER-SIDE REQUEST FORGERY (SSRF) — unrestricted proxy
// ----------------------------------------------------------------
app.post('/proxy', async (req, res) => {
  const target = req.body.url;
  // No allowlist validation — attacker can reach internal metadata endpoints
  // e.g. http://169.254.169.254/latest/meta-data/
  const response = await axios.post(target, req.body.data);
  res.send(response.data);
});

// ----------------------------------------------------------------
// CRITICAL: JWT SECRET HARDCODED + ALGORITHM CONFUSION
// ----------------------------------------------------------------
const jwt = require('jsonwebtoken');
const JWT_SECRET = 'weak_secret_123';   // hardcoded weak secret

app.post('/login', (req, res) => {
  const { username } = req.body;
  // HS256 with a hardcoded, weak secret — trivially brute-forceable
  const token = jwt.sign({ username, role: 'user' }, JWT_SECRET, { algorithm: 'HS256' });
  res.json({ token });
});

app.get('/admin', (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  // 'algorithms' not restricted — allows "alg: none" attack (CVE-2022-23529 class)
  const decoded = jwt.verify(token, JWT_SECRET);
  if (decoded.role !== 'admin') return res.status(403).send('Forbidden');
  res.send('Welcome admin');
});

// ----------------------------------------------------------------
// HIGH: OPEN REDIRECT
// ----------------------------------------------------------------
app.get('/redirect', (req, res) => {
  const target = req.query.to;
  // No domain validation — attacker can redirect users to phishing sites
  res.redirect(target);
});

// ----------------------------------------------------------------
// HIGH: PROTOTYPE POLLUTION via lodash merge
// ----------------------------------------------------------------
app.post('/merge-settings', (req, res) => {
  const userSettings = req.body.settings;
  const defaults = {};
  // _.merge with untrusted input allows __proto__ pollution
  const merged = _.merge(defaults, userSettings);
  res.json({ merged });
});

// ----------------------------------------------------------------
// HIGH: SENSITIVE DATA EXPOSURE — stack trace leaked to client
// ----------------------------------------------------------------
app.use((err, req, res, next) => {
  // Full stack trace exposed in production response
  res.status(500).json({ error: err.message, stack: err.stack });
});

// ----------------------------------------------------------------
// HIGH: BROKEN ACCESS CONTROL — user can access any account by ID
// ----------------------------------------------------------------
app.get('/account/:id', (req, res) => {
  const accountId = req.params.id;
  // No ownership check — any authenticated user can fetch any account
  const query = `SELECT * FROM accounts WHERE id = ${accountId}`;
  db.query(query, (err, results) => {
    if (err) return res.status(500).send(err.message);
    res.json(results);
  });
});

app.listen(3000, () => {
  console.log('Server running on port 3000');
});

