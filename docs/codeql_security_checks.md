# CodeQL Security Checks Overview

The framework uses **static analysis (CodeQL and Semgrep)** to identify potential vulnerabilities; findings are then **verified by the LLM** to reduce false positives. VulnHunterX integrates **CodeQL** and **Semgrep** for static code analysis. This document provides an overview of supported analysis tools, explains their query suites, and describes how they operate. For comprehensive details on checks and vulnerabilities for each language, see the language-specific documentation below.

## Language-Specific Documentation

| Language | Documentation | Query Suite |
|----------|--------------|-------------|
| **C/C++** | [codeql_cpp_security.md](codeql_cpp_security.md) | `codeql/cpp-queries:codeql-suites/cpp-security-extended.qls` |
| **Python** | [codeql_python_security.md](codeql_python_security.md) | `codeql/python-queries:codeql-suites/python-security-extended.qls` |
| **JavaScript/TypeScript** | [codeql_javascript_security.md](codeql_javascript_security.md) | `codeql/javascript-queries:codeql-suites/javascript-security-extended.qls` |

---

## How CodeQL Works

CodeQL is a semantic code analysis engine that treats code as data:

1. **Database Creation**: Source code is parsed into a relational database
2. **Query Execution**: Security queries run against the database
3. **Result Generation**: Findings output as SARIF (Static Analysis Results Interchange Format)

### Analysis Techniques

| Technique | Description | Use Case |
|-----------|-------------|----------|
| **Taint Tracking** | Traces data flow from untrusted sources to dangerous sinks | Injection vulnerabilities |
| **Data Flow Analysis** | Tracks how values propagate through the program | Finding where sensitive data goes |
| **Control Flow Analysis** | Analyzes execution paths and conditions | Use-after-free, null checks |
| **Pattern Matching** | Direct syntactic pattern detection | Hardcoded secrets, dangerous functions |

---

## Query Suites

| Suite | Description | When to Use |
|-------|-------------|-------------|
| `security-extended` | Security vulnerabilities only | Production security scanning |
| `security-and-quality` | Security + code quality | Comprehensive code review |
| `code-scanning` | GitHub default suite | CI/CD integration |

### Using Different Suites

```bash
# Security extended (default in this project)
codeql database analyze db --format=sarif --output=results.sarif \
    codeql/cpp-queries:codeql-suites/cpp-security-extended.qls

# Security and quality (more findings)
codeql database analyze db --format=sarif --output=results.sarif \
    codeql/cpp-queries:codeql-suites/cpp-security-and-quality.qls

# Specific CWE category
codeql database analyze db --format=sarif --output=results.sarif \
    codeql/cpp-queries:Security/CWE/CWE-120
```

---

## Taint Tracking: The Core Detection Method

Most injection vulnerabilities are detected through **taint tracking**:

```
┌─────────────────────────────────────────────────────────────┐
│                      TAINT TRACKING                         │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  SOURCES (Untrusted Data)                                   │
│  ├── HTTP requests (query, body, headers, cookies)          │
│  ├── Command line arguments (argv)                          │
│  ├── File reads (from untrusted locations)                  │
│  ├── Database queries (user-generated content)              │
│  ├── Environment variables                                  │
│  └── Network input (sockets, APIs)                          │
│                           │                                 │
│                           ▼                                 │
│  PROPAGATION (Taint Flows Through)                          │
│  ├── Variable assignments: y = x                            │
│  ├── String operations: concat, format, slice               │
│  ├── Object properties: obj.field = tainted                 │
│  ├── Array operations: arr.push(tainted)                    │
│  ├── Function calls and returns                             │
│  └── Type conversions                                       │
│                           │                                 │
│                           ▼                                 │
│  SINKS (Dangerous Operations)                               │
│  ├── SQL queries: cursor.execute(query)                     │
│  ├── Command execution: system(cmd), exec(cmd)              │
│  ├── File operations: open(path), readFile(path)            │
│  ├── HTML output: innerHTML, document.write()               │
│  ├── Code evaluation: eval(), Function()                    │
│  └── Network requests: fetch(url), axios.get(url)           │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Example: SQL Injection Detection

```python
# Source: HTTP request parameter
username = request.args.get('username')  # TAINTED

# Propagation: String formatting
query = f"SELECT * FROM users WHERE name = '{username}'"  # query is TAINTED

# Sink: SQL execution
cursor.execute(query)  # ALERT: Tainted data in SQL query
```

---

## Vulnerability Categories

### By CWE (Common Weakness Enumeration)

| CWE ID | Name | Languages | Severity |
|--------|------|-----------|----------|
| CWE-78 | OS Command Injection | All | Critical |
| CWE-79 | Cross-site Scripting (XSS) | JS, Python | High |
| CWE-89 | SQL Injection | All | Critical |
| CWE-94 | Code Injection | All | Critical |
| CWE-119 | Buffer Overflow | C/C++ | Critical |
| CWE-120 | Buffer Copy without Size Check | C/C++ | Critical |
| CWE-125 | Out-of-bounds Read | C/C++ | High |
| CWE-190 | Integer Overflow | C/C++ | High |
| CWE-200 | Information Exposure | All | Medium |
| CWE-22 | Path Traversal | All | High |
| CWE-312 | Cleartext Storage | All | Medium |
| CWE-327 | Weak Cryptography | All | Medium |
| CWE-416 | Use After Free | C/C++ | Critical |
| CWE-502 | Insecure Deserialization | JS, Python | Critical |
| CWE-611 | XXE Injection | All | High |
| CWE-798 | Hardcoded Credentials | All | High |
| CWE-918 | SSRF | JS, Python | High |
| CWE-1321 | Prototype Pollution | JS | High |

### By Impact

| Impact | Vulnerability Types |
|--------|---------------------|
| **Remote Code Execution** | Command injection, code injection, deserialization, buffer overflow |
| **Data Breach** | SQL injection, path traversal, XXE, SSRF |
| **Authentication Bypass** | Prototype pollution, JWT issues, weak crypto |
| **Session Hijacking** | XSS, insecure cookies, weak randomness |
| **Denial of Service** | ReDoS, resource leaks, integer overflow |

---

## Severity Levels

| Level | SARIF Value | Description | Action |
|-------|-------------|-------------|--------|
| **Error** | `error` | Confirmed security vulnerability | Fix immediately |
| **Warning** | `warning` | Likely security issue | Investigate and fix |
| **Note** | `note` | Possible issue or best practice | Review when possible |

---

## Understanding SARIF Output

CodeQL outputs results in SARIF format. Key fields:

```json
{
  "runs": [{
    "tool": {
      "driver": {
        "name": "CodeQL",
        "rules": [...]  // All rules that were checked
      }
    },
    "results": [{
      "ruleId": "cpp/sql-injection",
      "level": "error",
      "message": {
        "text": "This query depends on user-provided value..."
      },
      "locations": [{
        "physicalLocation": {
          "artifactLocation": { "uri": "src/db.cpp" },
          "region": { "startLine": 42 }
        }
      }],
      "codeFlows": [{
        "threadFlows": [{
          "locations": [...]  // Taint flow path from source to sink
        }]
      }]
    }]
  }]
}
```

### Reading Code Flows

The `codeFlows` section shows how tainted data flows:

```
Step 1: Source     → req.params.id (user input)
Step 2: Assignment → const id = req.params.id
Step 3: Formatting → const query = `SELECT * FROM users WHERE id = ${id}`
Step 4: Sink       → db.query(query) ← ALERT
```

---

## False Positive Handling

Not all findings are exploitable. Common false positive scenarios:

| Scenario | Example | Why It's False Positive |
|----------|---------|-------------------------|
| Input validated | `if (isValidId(id)) query(id)` | Validation prevents exploitation |
| Hardcoded value | `query("SELECT * FROM " + TABLE_NAME)` | TABLE_NAME is constant |
| Sanitized | `query(escapeHtml(input))` | Sanitization removes danger |
| Not user-reachable | Internal function not called with user input | No attack path |

### Suppressing False Positives

```python
# LGTM (Looks Good To Me) comment suppresses specific line
result = eval(trusted_expression)  # lgtm[py/code-injection]

# Or in CodeQL config file (.github/codeql/codeql-config.yml):
paths-ignore:
  - tests/**
  - vendor/**
```

---

## Quick Reference by Language

### C/C++ Top Vulnerabilities

1. Buffer Overflow (`cpp/overflow-buffer`)
2. Use After Free (`cpp/use-after-free`)
3. Command Injection (`cpp/command-line-injection`)
4. Format String (`cpp/tainted-format-string`)
5. Integer Overflow (`cpp/integer-overflow`)

→ See [C/C++ Security Checks](codeql_cpp_security.md)

### Python Top Vulnerabilities

1. SQL Injection (`py/sql-injection`)
2. Command Injection (`py/command-injection`)
3. Unsafe Deserialization (`py/unsafe-deserialization`)
4. XSS (`py/reflective-xss`)
5. SSRF (`py/server-side-request-forgery`)

→ See [Python Security Checks](codeql_python_security.md)

### JavaScript Top Vulnerabilities

1. Prototype Pollution (`js/prototype-pollution`)
2. Command Injection (`js/command-injection`)
3. XSS (`js/xss`, `js/xss-through-dom`)
4. SQL Injection (`js/sql-injection`)
5. Path Traversal (`js/path-injection`)

→ See [JavaScript Security Checks](codeql_javascript_security.md)

---

## References

- [CodeQL Documentation](https://codeql.github.com/docs/)
- [CodeQL Query Repository](https://github.com/github/codeql)
- [Semgrep Documentation](https://semgrep.dev/docs/)
- [CWE - Common Weakness Enumeration](https://cwe.mitre.org/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [SARIF Specification](https://sarifweb.azurewebsites.net/)
