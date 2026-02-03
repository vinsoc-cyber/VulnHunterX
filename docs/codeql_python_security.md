# CodeQL Python Security Checks

Comprehensive reference for CodeQL security queries targeting Python code.

**Query Suite**: `codeql/python-queries:codeql-suites/python-security-extended.qls`

---

## Table of Contents

1. [Injection Vulnerabilities](#injection-vulnerabilities)
2. [Cross-Site Scripting (XSS)](#cross-site-scripting-xss)
3. [Authentication and Session Issues](#authentication-and-session-issues)
4. [Cryptographic Issues](#cryptographic-issues)
5. [Deserialization Vulnerabilities](#deserialization-vulnerabilities)
6. [File and Path Vulnerabilities](#file-and-path-vulnerabilities)
7. [Server-Side Request Forgery (SSRF)](#server-side-request-forgery-ssrf)
8. [XML Vulnerabilities](#xml-vulnerabilities)
9. [Logging and Error Handling](#logging-and-error-handling)
10. [Framework-Specific Issues](#framework-specific-issues)

---

## Injection Vulnerabilities

### py/sql-injection (CWE-89)

**Vulnerability**: User input concatenated into SQL queries.

**CodeQL Discovery Flow**:
```
┌────────────────────────────────────────────────────────────────────────┐
│                 PYTHON SQL INJECTION DETECTION                         │
├────────────────────────────────────────────────────────────────────────┤
│                                                                        │
│  STEP 1: Define Taint Sources (Web Framework Inputs)                   │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │ Flask:                                                           │  │
│  │   request.args.get('param')    → Query string                    │  │
│  │   request.form['field']        → POST form data                  │  │
│  │   request.json                 → JSON body                       │  │
│  │   request.cookies              → Cookie values                   │  │
│  │                                                                  │  │
│  │ Django:                                                          │  │
│  │   request.GET['param']         → Query string                    │  │
│  │   request.POST['field']        → POST form data                  │  │
│  │   request.body                 → Raw body                        │  │
│  │                                                                  │  │
│  │ Generic:                                                         │  │
│  │   sys.argv, input(), open().read()                               │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                              │                                         │
│                              ▼                                         │
│  STEP 2: Track Taint Through String Operations                         │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │ "SELECT..." + tainted        → Result is tainted                 │  │
│  │ "SELECT...%s" % tainted      → Result is tainted                 │  │
│  │ f"SELECT...{tainted}"        → Result is tainted                 │  │
│  │ "SELECT...".format(tainted)  → Result is tainted                 │  │
│  │ tainted.upper()              → Result still tainted              │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                              │                                         │
│                              ▼                                         │
│  STEP 3: Define SQL Execution Sinks                                    │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │ cursor.execute(query)                → First arg is sink         │  │
│  │ cursor.executemany(query, ...)       → First arg is sink         │  │
│  │ connection.execute(query)            → SQLAlchemy                │  │
│  │ Model.objects.raw(query)             → Django raw SQL            │  │
│  │ session.execute(text(query))         → SQLAlchemy text           │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                              │                                         │
│                              ▼                                         │
│  STEP 4: Identify Safe Patterns (Sanitizers)                           │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │ cursor.execute("...%s...", (param,))  → Parameterized (SAFE)     │  │
│  │ Model.objects.filter(id=param)        → ORM method (SAFE)        │  │
│  │ text(q).bindparams(x=param)           → Bound params (SAFE)      │  │
│  │ These patterns BLOCK the taint flow                              │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                              │                                         │
│                              ▼                                         │
│  STEP 5: Report If Taint Reaches Sink                                  │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │ ALERT: SQL injection vulnerability                               │  │
│  │ CodeFlow: request.args['id'] → f"SELECT...{id}" → execute()      │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                                                                        │
└────────────────────────────────────────────────────────────────────────┘
```

**How CodeQL Detects It**:
- Identifies SQL execution: `cursor.execute()`, ORM raw queries
- Taint-tracks from request inputs (Flask: `request.args`, Django: `request.GET`)
- Detects string formatting/concatenation in queries
- Recognizes safe parameterized patterns

**Vulnerable Code**:
```python
# String concatenation
query = "SELECT * FROM users WHERE id = " + user_id
cursor.execute(query)  # ALERT

# String formatting
query = "SELECT * FROM users WHERE name = '%s'" % username
cursor.execute(query)  # ALERT

# f-strings
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")  # ALERT
```

**Attack Example**:
```python
user_id = "1 OR 1=1; DROP TABLE users;--"
# Query becomes: SELECT * FROM users WHERE id = 1 OR 1=1; DROP TABLE users;--
```

**Safe Patterns (Not Flagged)**:
```python
# Parameterized query - values passed separately
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))

# Django ORM
User.objects.filter(id=user_id)

# SQLAlchemy with bound parameters
session.query(User).filter(User.id == user_id)
```

---

### py/command-injection (CWE-78)

**Vulnerability**: User input passed to shell command execution.

**CodeQL Discovery Flow**:
```
┌────────────────────────────────────────────────────────────────────────┐
│                PYTHON COMMAND INJECTION DETECTION                      │
├────────────────────────────────────────────────────────────────────────┤
│                                                                        │
│  STEP 1: Identify Command Execution Sinks                              │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │ ALWAYS SHELL (High Risk):                                        │  │
│  │   os.system(cmd)              → Always uses shell                │  │
│  │   os.popen(cmd)               → Always uses shell                │  │
│  │                                                                  │  │
│  │ CONDITIONAL SHELL:                                               │  │
│  │   subprocess.call(cmd, shell=True)    → Shell if shell=True      │  │
│  │   subprocess.run(cmd, shell=True)     → Shell if shell=True      │  │
│  │   subprocess.Popen(cmd, shell=True)   → Shell if shell=True      │  │
│  │                                                                  │  │
│  │ SAFE (No Shell):                                                 │  │
│  │   subprocess.run(['ping', host])      → Args as list, no shell   │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                              │                                         │
│                              ▼                                         │
│  STEP 2: Track Taint to Command String                                 │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │ "ping " + user_input           → Tainted command string          │  │
│  │ f"echo {user_input}"           → Tainted command string          │  │
│  │ shlex.join(['cmd', user_input])→ Still tainted if shell=True     │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                              │                                         │
│                              ▼                                         │
│  STEP 3: Check for Sanitization                                        │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │ shlex.quote(user_input)        → Properly escapes for shell      │  │
│  │ pipes.quote(user_input)        → Legacy escaping                 │  │
│  │ Validation (regex whitelist)   → Blocks unexpected chars         │  │
│  │ These BLOCK taint propagation                                    │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                              │                                         │
│                              ▼                                         │
│  STEP 4: Report Injection Path                                         │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │ ALERT: Command injection                                         │  │
│  │ CodeFlow: request.args['host'] → "ping "+host → os.system()      │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                                                                        │
└────────────────────────────────────────────────────────────────────────┘
```

**How CodeQL Detects It**:
- Identifies dangerous functions: `os.system()`, `os.popen()`, `subprocess.call()` with `shell=True`
- Taint-tracks from user input sources
- Checks for shell metacharacter sanitization

**Vulnerable Code**:
```python
import os
import subprocess

# os.system - always uses shell
os.system("ping " + user_host)  # ALERT

# subprocess with shell=True
subprocess.call("echo " + user_input, shell=True)  # ALERT

# os.popen
os.popen("cat " + filename)  # ALERT
```

**Attack Example**:
```python
user_host = "localhost; cat /etc/passwd"
# Executes: ping localhost; cat /etc/passwd
```

**Safe Patterns**:
```python
# subprocess without shell
subprocess.run(["ping", user_host])  # Arguments are not interpreted by shell

# shlex.quote for shell commands
import shlex
subprocess.call(f"ping {shlex.quote(user_host)}", shell=True)
```

---

### py/code-injection (CWE-94)

**Vulnerability**: User input passed to code execution functions.

**How CodeQL Detects It**:
- Identifies: `eval()`, `exec()`, `compile()`, `__import__()`
- Taint-tracks from user inputs
- Very high severity - direct code execution

**Vulnerable Code**:
```python
# eval with user input
result = eval(user_expression)  # ALERT

# exec with user input
exec(user_code)  # ALERT

# Dynamic import
module = __import__(user_module_name)  # ALERT
```

**Attack Example**:
```python
user_expression = "__import__('os').system('rm -rf /')"
eval(user_expression)  # Executes arbitrary command
```

**Safe Alternatives**:
```python
# For math expressions
import ast
result = ast.literal_eval(user_expression)  # Only evaluates literals

# For specific operations, use explicit logic
operations = {'+': lambda a, b: a + b, '-': lambda a, b: a - b}
result = operations[op](a, b)
```

---

### py/ldap-injection (CWE-90)

**Vulnerability**: User input in LDAP queries without escaping.

**How CodeQL Detects It**:
- Identifies LDAP search calls
- Tracks user input to filter strings
- Checks for ldap.filter.escape_filter_chars()

**Vulnerable Code**:
```python
import ldap

filter_str = f"(uid={username})"  # ALERT
conn.search_s("dc=example,dc=com", ldap.SCOPE_SUBTREE, filter_str)
```

**Attack Example**:
```python
username = "*)(uid=*))(|(uid=*"
# Filter becomes: (uid=*)(uid=*))(|(uid=*)
# Returns all users
```

**Fix**:
```python
from ldap.filter import escape_filter_chars
filter_str = f"(uid={escape_filter_chars(username)})"
```

---

### py/regex-injection (CWE-1333)

**Vulnerability**: User input used in regular expression (ReDoS).

**How CodeQL Detects It**:
- Identifies `re.compile()`, `re.match()`, `re.search()` with user input
- Tracks taint to regex pattern argument

**Vulnerable Code**:
```python
import re
pattern = re.compile(user_pattern)  # ALERT
pattern.match(data)
```

**Attack Example (ReDoS)**:
```python
# Catastrophic backtracking pattern
user_pattern = "(a+)+"
data = "a" * 30 + "!"
# Regex engine tries exponentially many paths
```

**Fix**:
```python
# Escape user input if using as literal
pattern = re.compile(re.escape(user_pattern))

# Or use timeout (Python 3.11+)
re.match(pattern, data, timeout=1.0)
```

---

## Cross-Site Scripting (XSS)

### py/reflective-xss (CWE-79)

**Vulnerability**: Request data reflected in response without escaping.

**CodeQL Discovery Flow**:
```
┌────────────────────────────────────────────────────────────────────────┐
│                    PYTHON XSS DETECTION                                │
├────────────────────────────────────────────────────────────────────────┤
│                                                                        │
│  STEP 1: Identify HTTP Response Sinks                                  │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │ Flask:                                                           │  │
│  │   return "html string"         → Direct response                 │  │
│  │   Response("html")             → Response object                 │  │
│  │   make_response("html")        → Response helper                 │  │
│  │                                                                  │  │
│  │ Django:                                                          │  │
│  │   HttpResponse("html")         → Direct response                 │  │
│  │   render_to_string(...)        → Template rendering              │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                              │                                         │
│                              ▼                                         │
│  STEP 2: Track Request Data to Response                                │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │ request.args.get('q')  ─────────────────────────────┐            │  │
│  │         │                                            │            │  │
│  │         ▼                                            │            │  │
│  │ query = request.args.get('q')      (tainted)        │            │  │
│  │         │                                            │            │  │
│  │         ▼                                            │            │  │
│  │ html = f"<h1>{query}</h1>"         (tainted HTML)   │            │  │
│  │         │                                            │            │  │
│  │         ▼                                            │            │  │
│  │ return html                        → SINK (ALERT)   │            │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                              │                                         │
│                              ▼                                         │
│  STEP 3: Check for Sanitization                                        │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │ escape(query)                  → Blocks taint (SAFE)             │  │
│  │ markupsafe.escape(query)       → Blocks taint (SAFE)             │  │
│  │ render_template('t.html', q=q) → Auto-escape (SAFE)              │  │
│  │ Markup(query)                  → Does NOT sanitize (UNSAFE)      │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                              │                                         │
│                              ▼                                         │
│  STEP 4: Report XSS Vulnerability                                      │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │ ALERT: Reflected XSS                                             │  │
│  │ CodeFlow: request.args['q'] → f"<h1>{q}</h1>" → return           │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                                                                        │
└────────────────────────────────────────────────────────────────────────┘
```

**How CodeQL Detects It**:
- Tracks from request inputs to response outputs
- Identifies unsafe response construction
- Checks for HTML escaping/template auto-escaping

**Vulnerable Code (Flask)**:
```python
from flask import Flask, request

@app.route('/search')
def search():
    query = request.args.get('q')
    return f"<h1>Results for: {query}</h1>"  # ALERT: XSS
```

**Attack**:
```
GET /search?q=<script>alert('XSS')</script>
```

**Safe Patterns**:
```python
# Flask with Jinja2 template (auto-escapes)
from flask import render_template
return render_template('search.html', query=query)

# Manual escaping
from markupsafe import escape
return f"<h1>Results for: {escape(query)}</h1>"
```

---

### py/stored-xss (CWE-79)

**Vulnerability**: Data from database displayed without escaping.

**How CodeQL Detects It**:
- Tracks from database read to response output
- Considers data may have been user-supplied originally

**Vulnerable Code**:
```python
@app.route('/user/<int:id>')
def profile(id):
    user = User.query.get(id)
    return f"<h1>Bio: {user.bio}</h1>"  # ALERT: user.bio may contain script
```

---

### py/jinja2-autoescape-false (CWE-79)

**Vulnerability**: Jinja2 template with autoescape disabled.

**How CodeQL Detects It**:
- Checks Jinja2 Environment configuration
- Flags `autoescape=False`

**Vulnerable Code**:
```python
from jinja2 import Environment

env = Environment(autoescape=False)  # ALERT
template = env.from_string("<p>{{ user_input }}</p>")
```

**Fix**:
```python
from jinja2 import Environment, select_autoescape

env = Environment(autoescape=select_autoescape(['html', 'xml']))
```

---

## Authentication and Session Issues

### py/weak-sensitive-data-hashing (CWE-916)

**Vulnerability**: Passwords hashed with weak algorithm.

**How CodeQL Detects It**:
- Identifies password-related variables
- Checks hash algorithm used (MD5, SHA1)
- Flags missing salt or iterations

**Vulnerable Code**:
```python
import hashlib

password_hash = hashlib.md5(password.encode()).hexdigest()  # ALERT
password_hash = hashlib.sha1(password.encode()).hexdigest()  # ALERT
```

**Safe Patterns**:
```python
# bcrypt
import bcrypt
password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

# Argon2
from argon2 import PasswordHasher
ph = PasswordHasher()
password_hash = ph.hash(password)

# PBKDF2
import hashlib
password_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
```

---

### py/missing-rate-limiting (CWE-307)

**Vulnerability**: Authentication endpoint without rate limiting.

**How CodeQL Detects It**:
- Identifies login/auth endpoints
- Checks for rate limiting middleware/decorators

**Vulnerable Code**:
```python
@app.route('/login', methods=['POST'])
def login():  # ALERT: No rate limiting
    if check_password(request.form['password']):
        return create_session()
```

**Fix**:
```python
from flask_limiter import Limiter

limiter = Limiter(app)

@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    ...
```

---

### py/insecure-cookie (CWE-614)

**Vulnerability**: Session cookie without Secure or HttpOnly flags.

**How CodeQL Detects It**:
- Identifies cookie setting operations
- Checks for missing security flags

**Vulnerable Code**:
```python
response.set_cookie('session_id', token)  # ALERT: Missing flags
```

**Fix**:
```python
response.set_cookie('session_id', token, 
    secure=True,      # Only over HTTPS
    httponly=True,    # Not accessible via JavaScript
    samesite='Strict' # CSRF protection
)
```

---

## Cryptographic Issues

### py/weak-cryptographic-algorithm (CWE-327)

**Vulnerability**: Use of weak or broken cryptographic algorithms.

**How CodeQL Detects It**:
- Identifies crypto module usage
- Matches weak algorithm names

**Weak Algorithms**:
| Algorithm | Issue | Replacement |
|-----------|-------|-------------|
| MD5 | Collisions | SHA-256, SHA-3 |
| SHA-1 | Collisions | SHA-256, SHA-3 |
| DES | 56-bit key | AES-256 |
| RC4 | Biased output | AES-GCM |
| ECB mode | Pattern preservation | CBC, GCM |

**Vulnerable Code**:
```python
from Crypto.Cipher import DES
cipher = DES.new(key, DES.MODE_ECB)  # ALERT: DES and ECB

import hashlib
hashlib.md5(data)  # ALERT for security-sensitive use
```

**Fix**:
```python
from Crypto.Cipher import AES
cipher = AES.new(key, AES.MODE_GCM)

from hashlib import sha256
sha256(data)
```

---

### py/insecure-randomness (CWE-330)

**Vulnerability**: Using `random` module for security-sensitive operations.

**How CodeQL Detects It**:
- Identifies use of `random` module
- Checks context: token generation, password generation, crypto keys

**Vulnerable Code**:
```python
import random

token = ''.join(random.choices(string.ascii_letters, k=32))  # ALERT
session_id = random.randint(0, 1000000)  # ALERT
```

**Why It's Dangerous**:
- `random` uses Mersenne Twister (predictable)
- Given 624 outputs, entire sequence can be predicted

**Fix**:
```python
import secrets

token = secrets.token_urlsafe(32)
session_id = secrets.randbelow(1000000)
```

---

### py/cleartext-storage-sensitive-data (CWE-312)

**Vulnerability**: Sensitive data stored without encryption.

**How CodeQL Detects It**:
- Identifies sensitive variables (password, secret, key)
- Tracks to file write or database storage
- Checks for encryption before storage

**Vulnerable Code**:
```python
with open('config.json', 'w') as f:
    json.dump({'api_key': api_key}, f)  # ALERT
```

---

## Deserialization Vulnerabilities

### py/unsafe-deserialization (CWE-502)

**Vulnerability**: Deserializing untrusted data with dangerous functions.

**CodeQL Discovery Flow**:
```
┌────────────────────────────────────────────────────────────────────────┐
│               UNSAFE DESERIALIZATION DETECTION                         │
├────────────────────────────────────────────────────────────────────────┤
│                                                                        │
│  STEP 1: Identify Dangerous Deserialization Functions (Sinks)         │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │ CRITICAL RISK (Arbitrary Code Execution):                       │  │
│  │   pickle.loads(data)           → Executes __reduce__            │  │
│  │   pickle.load(file)            → Same as loads                  │  │
│  │   cPickle.loads(data)          → Python 2 pickle                │  │
│  │   yaml.load(data)              → Before PyYAML 5.1              │  │
│  │   yaml.unsafe_load(data)       → Explicitly unsafe              │  │
│  │   marshal.loads(data)          → Bytecode execution             │  │
│  │   shelve.open(filename)        → Uses pickle internally         │  │
│  │   dill.loads(data)             → Extended pickle                │  │
│  │   jsonpickle.decode(data)      → JSON + pickle                  │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                              │                                         │
│                              ▼                                         │
│  STEP 2: Identify Untrusted Data Sources                               │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │ HTTP request body:                                               │  │
│  │   request.data, request.get_data()                               │  │
│  │ HTTP parameters:                                                 │  │
│  │   request.args.get('data')                                       │  │
│  │ File uploads:                                                    │  │
│  │   request.files['file'].read()                                   │  │
│  │ Network data:                                                    │  │
│  │   socket.recv(), urllib.urlopen().read()                         │  │
│  │ Database (if user-originated):                                   │  │
│  │   cursor.fetchone()[0]  # If column contains serialized data    │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                              │                                         │
│                              ▼                                         │
│  STEP 3: Track Data Flow from Source to Sink                          │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │ data = request.data                   (tainted)                  │  │
│  │         │                                                        │  │
│  │         ▼                                                        │  │
│  │ decoded = base64.b64decode(data)      (still tainted)            │  │
│  │         │                                                        │  │
│  │         ▼                                                        │  │
│  │ obj = pickle.loads(decoded)           → SINK (ALERT!)           │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                              │                                         │
│                              ▼                                         │
│  STEP 4: Identify Safe Alternatives (Not Flagged)                      │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │ json.loads(data)               → Safe, no code execution        │  │
│  │ yaml.safe_load(data)           → Safe subset of YAML            │  │
│  │ ast.literal_eval(data)         → Only literals                  │  │
│  │ HMAC-verified then pickle      → Authenticated (less risk)      │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                              │                                         │
│                              ▼                                         │
│  STEP 5: Report Vulnerability                                          │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │ ALERT: Unsafe deserialization of untrusted data                  │  │
│  │ Severity: CRITICAL (Remote Code Execution)                       │  │
│  │ CodeFlow: request.data → base64.decode → pickle.loads           │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                                                                        │
└────────────────────────────────────────────────────────────────────────┘
```

**How CodeQL Detects It**:
- Identifies: `pickle.loads()`, `yaml.load()`, `marshal.loads()`
- Tracks from untrusted sources (network, user input)

**Dangerous Functions**:
| Function | Risk |
|----------|------|
| `pickle.loads()` | Arbitrary code execution |
| `yaml.load()` | Arbitrary code execution |
| `marshal.loads()` | Code execution |
| `shelve.open()` | Uses pickle |
| `jsonpickle.decode()` | Code execution |

**Vulnerable Code**:
```python
import pickle
data = pickle.loads(request.data)  # ALERT: RCE

import yaml
config = yaml.load(user_yaml)  # ALERT: RCE (before pyyaml 5.1)
```

**Attack (Pickle)**:
```python
import pickle
import os

class Exploit:
    def __reduce__(self):
        return (os.system, ('rm -rf /',))

payload = pickle.dumps(Exploit())
# When unpickled, executes os.system('rm -rf /')
```

**Fix**:
```python
# Use JSON instead
import json
data = json.loads(request.data)

# If YAML needed, use safe_load
import yaml
config = yaml.safe_load(user_yaml)

# If pickle needed, use hmac signature
import hmac
signature = hmac.new(secret_key, data, 'sha256').hexdigest()
# Verify signature before unpickling
```

---

## File and Path Vulnerabilities

### py/path-injection (CWE-22)

**Vulnerability**: User input in file path operations.

**How CodeQL Detects It**:
- Identifies file operations: `open()`, `os.path.join()`, `pathlib.Path()`
- Taint-tracks from user input
- Checks for path traversal patterns

**Vulnerable Code**:
```python
filename = request.args.get('file')
with open(f'/var/data/{filename}', 'r') as f:  # ALERT
    return f.read()
```

**Attack**:
```
GET /download?file=../../../etc/passwd
```

**Fix**:
```python
import os

filename = request.args.get('file')
# Validate: no path separators
if '/' in filename or '\\' in filename or '..' in filename:
    abort(400)

# Or resolve and verify prefix
base = '/var/data'
full_path = os.path.realpath(os.path.join(base, filename))
if not full_path.startswith(base):
    abort(400)
```

---

### py/tarslip (CWE-22)

**Vulnerability**: Extracting tar archive with path traversal.

**How CodeQL Detects It**:
- Identifies `tarfile.extractall()` calls
- Checks for path validation before extraction

**Vulnerable Code**:
```python
import tarfile

with tarfile.open(uploaded_file) as tar:
    tar.extractall('/var/data')  # ALERT: Tar slip
```

**Attack**:
Malicious tar contains: `../../etc/cron.d/malicious`

**Fix**:
```python
import tarfile
import os

def safe_extract(tar, path):
    for member in tar.getmembers():
        member_path = os.path.join(path, member.name)
        if not os.path.realpath(member_path).startswith(os.path.realpath(path)):
            raise Exception("Path traversal detected")
    tar.extractall(path)
```

---

## Server-Side Request Forgery (SSRF)

### py/server-side-request-forgery (CWE-918)

**Vulnerability**: User input controls URL in server-side HTTP request.

**How CodeQL Detects It**:
- Identifies HTTP request functions: `requests.get()`, `urllib.urlopen()`
- Tracks user input to URL parameter
- Checks for URL validation

**Vulnerable Code**:
```python
import requests

url = request.args.get('url')
response = requests.get(url)  # ALERT: SSRF
return response.text
```

**Attack**:
```
# Access internal services
GET /fetch?url=http://169.254.169.254/latest/meta-data/  # AWS metadata
GET /fetch?url=http://localhost:6379/  # Redis
GET /fetch?url=file:///etc/passwd  # Local files
```

**Fix**:
```python
from urllib.parse import urlparse

url = request.args.get('url')
parsed = urlparse(url)

# Allowlist approach
ALLOWED_HOSTS = ['api.example.com', 'cdn.example.com']
if parsed.hostname not in ALLOWED_HOSTS:
    abort(400)

# Block internal IPs
import ipaddress
try:
    ip = ipaddress.ip_address(parsed.hostname)
    if ip.is_private or ip.is_loopback:
        abort(400)
except ValueError:
    pass  # Not an IP, resolve and check

response = requests.get(url)
```

---

### py/request-without-cert-validation (CWE-295)

**Vulnerability**: HTTPS request with certificate verification disabled.

**How CodeQL Detects It**:
- Identifies `verify=False` in requests
- Checks SSL context configuration

**Vulnerable Code**:
```python
import requests
requests.get('https://api.example.com', verify=False)  # ALERT

import ssl
context = ssl._create_unverified_context()  # ALERT
```

**Why It's Dangerous**:
- Man-in-the-middle attacks possible
- Attacker can intercept and modify traffic

**Fix**:
```python
# Use default verification
requests.get('https://api.example.com')

# Or specify CA bundle
requests.get('https://api.example.com', verify='/path/to/ca-bundle.crt')
```

---

## XML Vulnerabilities

### py/xml-external-entity-injection (CWE-611)

**Vulnerability**: XML parser processes external entities.

**How CodeQL Detects It**:
- Identifies XML parsing with defusedxml alternatives not used
- Checks parser configuration

**Vulnerable Code**:
```python
from lxml import etree
doc = etree.parse(user_xml)  # ALERT: XXE

import xml.etree.ElementTree as ET
ET.parse(user_xml)  # ALERT in older Python
```

**Attack**:
```xml
<?xml version="1.0"?>
<!DOCTYPE data [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<data>&xxe;</data>
```

**Fix**:
```python
# Use defusedxml
import defusedxml.ElementTree as ET
doc = ET.parse(user_xml)

# Or disable entities in lxml
from lxml import etree
parser = etree.XMLParser(resolve_entities=False, no_network=True)
doc = etree.parse(user_xml, parser)
```

---

## Logging and Error Handling

### py/clear-text-logging-sensitive-data (CWE-532)

**Vulnerability**: Sensitive data written to logs.

**How CodeQL Detects It**:
- Identifies sensitive variables
- Tracks to logging functions

**Vulnerable Code**:
```python
import logging

logging.info(f"User {user} logged in with password {password}")  # ALERT
logger.debug(f"API key: {api_key}")  # ALERT
```

**Fix**:
```python
logging.info(f"User {user} logged in")  # Don't log passwords
logger.debug("API key: [REDACTED]")
```

---

### py/exception-info-exposure (CWE-209)

**Vulnerability**: Stack trace exposed to user.

**How CodeQL Detects It**:
- Identifies exception handling that returns traceback to response

**Vulnerable Code**:
```python
import traceback

@app.errorhandler(Exception)
def handle_error(e):
    return traceback.format_exc(), 500  # ALERT: Info disclosure
```

**Fix**:
```python
@app.errorhandler(Exception)
def handle_error(e):
    app.logger.exception("Unhandled error")  # Log full traceback
    return "Internal server error", 500  # Generic message to user
```

---

## Framework-Specific Issues

### Flask

| Check ID | Issue |
|----------|-------|
| `py/flask-debug` | `app.run(debug=True)` in production |
| `py/flask-hardcoded-secret` | `app.secret_key = "..."` hardcoded |

**Vulnerable Code**:
```python
app = Flask(__name__)
app.secret_key = "supersecret123"  # ALERT
app.run(debug=True)  # ALERT in production
```

---

### Django

| Check ID | Issue |
|----------|-------|
| `py/django-debug-mode-enabled` | `DEBUG = True` in production |
| `py/django-secret-key-in-source` | `SECRET_KEY` hardcoded |
| `py/django-csrf-disabled` | CSRF middleware removed |

**Vulnerable Code (settings.py)**:
```python
DEBUG = True  # ALERT in production
SECRET_KEY = 'django-insecure-abc123'  # ALERT
MIDDLEWARE = [
    # 'django.middleware.csrf.CsrfViewMiddleware',  # ALERT if removed
]
```

---

## Summary: Top 10 Python Vulnerabilities

| Priority | Vulnerability | CWE | Impact |
|----------|--------------|-----|--------|
| 1 | SQL Injection | CWE-89 | Data breach |
| 2 | Command Injection | CWE-78 | Code execution |
| 3 | Code Injection (eval) | CWE-94 | Code execution |
| 4 | Unsafe Deserialization | CWE-502 | Code execution |
| 5 | XSS | CWE-79 | Session hijacking |
| 6 | Path Traversal | CWE-22 | Data access |
| 7 | SSRF | CWE-918 | Internal access |
| 8 | XXE | CWE-611 | Data access |
| 9 | Weak Crypto | CWE-327 | Data exposure |
| 10 | Insecure Deserialization | CWE-502 | Code execution |

---

## References

- [CodeQL Python Queries](https://github.com/github/codeql/tree/main/python/ql/src)
- [OWASP Python Security](https://cheatsheetseries.owasp.org/cheatsheets/Python_Security_Cheat_Sheet.html)
- [Bandit - Python Security Linter](https://bandit.readthedocs.io/)
- [Flask Security Considerations](https://flask.palletsprojects.com/en/2.0.x/security/)
- [Django Security](https://docs.djangoproject.com/en/4.0/topics/security/)
