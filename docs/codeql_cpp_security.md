# CodeQL C/C++ Security Checks

Comprehensive reference for CodeQL security queries targeting C and C++ code.

**Query Suite**: `codeql/cpp-queries:codeql-suites/cpp-security-extended.qls`

---

## Table of Contents

1. [Memory Safety Vulnerabilities](#memory-safety-vulnerabilities)
2. [Buffer Overflow and Bounds Checking](#buffer-overflow-and-bounds-checking)
3. [Injection Vulnerabilities](#injection-vulnerabilities)
4. [Integer Vulnerabilities](#integer-vulnerabilities)
5. [Cryptographic Issues](#cryptographic-issues)
6. [Resource Management](#resource-management)
7. [Dangerous Functions](#dangerous-functions)
8. [Null Pointer Issues](#null-pointer-issues)
9. [Race Conditions](#race-conditions)
10. [Information Disclosure](#information-disclosure)

---

## Memory Safety Vulnerabilities

### cpp/use-after-free (CWE-416)

**Vulnerability**: Accessing memory after it has been freed.

**CodeQL Discovery Flow**:
```
┌────────────────────────────────────────────────────────────────────────┐
│                     USE-AFTER-FREE DETECTION                           │
├────────────────────────────────────────────────────────────────────────┤
│                                                                        │
│  STEP 1: Identify Allocation Points                                    │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │ Query: Find all malloc(), calloc(), realloc(), new, new[]        │  │
│  │ Result: AllocationExpr with associated pointer variable          │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                              │                                         │
│                              ▼                                         │
│  STEP 2: Track Pointer Aliases                                         │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │ ptr2 = ptr1;  // ptr2 is now an alias                            │  │
│  │ func(ptr1);   // ptr may be stored elsewhere                     │  │
│  │ Build alias set for each allocation                              │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                              │                                         │
│                              ▼                                         │
│  STEP 3: Find Deallocation Points                                      │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │ Query: Find free(ptr), delete ptr, delete[] ptr                  │  │
│  │ Mark: Pointer and all aliases as "freed" at this program point   │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                              │                                         │
│                              ▼                                         │
│  STEP 4: Control Flow Analysis (Path-Sensitive)                        │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │ For each path from free() to function exit:                      │  │
│  │   - Track pointer state: FREED                                   │  │
│  │   - Consider conditionals: if(ptr) doesn't reset state           │  │
│  │   - Consider reassignment: ptr = malloc() resets to VALID        │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                              │                                         │
│                              ▼                                         │
│  STEP 5: Find Use After Free                                           │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │ Query: Find dereference (*ptr), array access (ptr[i]),           │  │
│  │        function call (func(ptr)) where ptr state is FREED        │  │
│  │ ALERT: Use of freed pointer detected                             │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                                                                        │
└────────────────────────────────────────────────────────────────────────┘
```

**How CodeQL Detects It**:
- Tracks calls to `free()`, `delete`, `delete[]`
- Follows control flow to find subsequent uses of the freed pointer
- Considers aliasing (multiple pointers to same memory)

**Vulnerable Code**:
```c
char *ptr = malloc(100);
// ... use ptr ...
free(ptr);
printf("%s", ptr);  // ALERT: Use after free
```

**Why It's Dangerous**:
- Memory may be reallocated to another object
- Attacker can control freed memory contents
- Can lead to arbitrary code execution

**Fix**:
```c
free(ptr);
ptr = NULL;  // Prevent accidental use
```

---

### cpp/double-free (CWE-415)

**Vulnerability**: Freeing the same memory location twice.

**CodeQL Discovery Flow**:
```
┌────────────────────────────────────────────────────────────────────────┐
│                      DOUBLE-FREE DETECTION                             │
├────────────────────────────────────────────────────────────────────────┤
│                                                                        │
│  STEP 1: Build Free-Call Graph                                         │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │ For each pointer P:                                              │  │
│  │   Collect all free(P) call sites                                 │  │
│  │   Record program location and control flow context               │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                              │                                         │
│                              ▼                                         │
│  STEP 2: Path Analysis Between Frees                                   │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │ For each pair of free(P) calls (F1, F2):                         │  │
│  │   Question: Is there a path from F1 to F2?                       │  │
│  │   Check: Is P reassigned between F1 and F2?                      │  │
│  │          P = malloc() → NOT double-free                          │  │
│  │          P = other_ptr → Still could be double-free              │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                              │                                         │
│                              ▼                                         │
│  STEP 3: Alias-Aware Analysis                                          │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │ Check: free(ptr1) followed by free(ptr2)                         │  │
│  │        where ptr1 and ptr2 may alias same memory                 │  │
│  │ Example: ptr2 = ptr1; free(ptr1); free(ptr2);                    │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                              │                                         │
│                              ▼                                         │
│  STEP 4: Report                                                        │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │ ALERT: Double free detected                                      │  │
│  │ CodeFlow: First free → Second free (with intermediate path)      │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                                                                        │
└────────────────────────────────────────────────────────────────────────┘
```

**How CodeQL Detects It**:
- Tracks all `free()` calls on each pointer
- Uses path-sensitive analysis to find paths where same pointer is freed twice
- Considers pointer assignments and aliasing

**Vulnerable Code**:
```c
char *ptr = malloc(100);
free(ptr);
// ... other code ...
free(ptr);  // ALERT: Double free
```

**Why It's Dangerous**:
- Corrupts heap metadata
- Can lead to arbitrary write primitive
- Enables heap exploitation techniques

**Fix**:
```c
free(ptr);
ptr = NULL;  // Second free(NULL) is safe
```

---

### cpp/stack-address-escape (CWE-562)

**Vulnerability**: Returning or storing address of stack-allocated variable.

**CodeQL Discovery Flow**:
```
┌────────────────────────────────────────────────────────────────────────┐
│                   STACK ADDRESS ESCAPE DETECTION                       │
├────────────────────────────────────────────────────────────────────────┤
│                                                                        │
│  STEP 1: Identify Stack Variables                                      │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │ Query: Find local variables (auto storage duration)              │  │
│  │        int x;  char buf[100];  struct S obj;                     │  │
│  │ NOT:   static int x;  // Not stack                               │  │
│  │        malloc(100);   // Not stack                               │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                              │                                         │
│                              ▼                                         │
│  STEP 2: Find Address-Of Operations                                   │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │ Query: &localVar, localArray (decays to pointer)                 │  │
│  │ Track: Where does this address flow?                             │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                              │                                         │
│                              ▼                                         │
│  STEP 3: Escape Analysis                                               │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │ Check if address escapes function scope:                         │  │
│  │   return &local;           → ESCAPES via return                  │  │
│  │   *global_ptr = &local;    → ESCAPES via global                  │  │
│  │   heap_obj->ptr = &local;  → ESCAPES via heap                    │  │
│  │   async_callback(&local);  → ESCAPES via callback                │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                              │                                         │
│                              ▼                                         │
│  STEP 4: Report Escaping Addresses                                     │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │ ALERT: Stack address escapes function scope                      │  │
│  │ CodeFlow: Local variable → &var → escape point                   │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                                                                        │
└────────────────────────────────────────────────────────────────────────┘
```

**How CodeQL Detects It**:
- Identifies local variables (stack-allocated)
- Tracks when their address is returned or stored in global/heap memory
- Follows pointer assignments through function calls

**Vulnerable Code**:
```c
int* getPointer() {
    int local = 42;
    return &local;  // ALERT: Stack address escape
}
```

**Why It's Dangerous**:
- Stack frame is deallocated when function returns
- Returned pointer points to invalid memory
- Reading returns garbage; writing corrupts stack

**Fix**:
```c
int* getPointer() {
    int *ptr = malloc(sizeof(int));
    *ptr = 42;
    return ptr;  // Caller must free
}
```

---

## Buffer Overflow and Bounds Checking

### cpp/overflow-buffer (CWE-120)

**Vulnerability**: Writing beyond the bounds of a buffer.

**CodeQL Discovery Flow**:
```
┌────────────────────────────────────────────────────────────────────────┐
│                    BUFFER OVERFLOW DETECTION                           │
├────────────────────────────────────────────────────────────────────────┤
│                                                                        │
│  STEP 1: Identify Buffer Allocations                                   │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │ char buf[100];           → Size: 100 bytes                       │  │
│  │ malloc(n);               → Size: n bytes (track n value)         │  │
│  │ char *p = "literal";     → Size: strlen + 1                      │  │
│  │ Build: BufferAllocation(ptr, size, location)                     │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                              │                                         │
│                              ▼                                         │
│  STEP 2: Identify Copy/Write Operations (Sinks)                        │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │ strcpy(dest, src)      → Copies strlen(src)+1 bytes              │  │
│  │ memcpy(dest, src, n)   → Copies n bytes                          │  │
│  │ sprintf(buf, fmt, ...) → Variable size output                    │  │
│  │ gets(buf)              → Unlimited input                         │  │
│  │ dest[i] = x            → Single byte at offset i                 │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                              │                                         │
│                              ▼                                         │
│  STEP 3: Range/Size Analysis                                           │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │ For each (buffer, write_operation) pair:                         │  │
│  │   dest_size = known buffer size                                  │  │
│  │   write_size = computed or estimated write size                  │  │
│  │   Check: write_size > dest_size?                                 │  │
│  │   Consider: Loop bounds, string lengths, user input              │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                              │                                         │
│                              ▼                                         │
│  STEP 4: Report Overflow                                               │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │ ALERT: Buffer overflow detected                                  │  │
│  │ Details: Buffer size X, write size Y (Y > X)                     │  │
│  │ CodeFlow: Buffer allocation → Write operation                    │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                                                                        │
└────────────────────────────────────────────────────────────────────────┘
```

**How CodeQL Detects It**:
- Tracks buffer allocations and their sizes
- Analyzes copy operations (memcpy, strcpy, etc.)
- Compares source size with destination capacity
- Uses range analysis for loop-based copies

**Vulnerable Code**:
```c
char dest[10];
char *src = "This is a very long string";
strcpy(dest, src);  // ALERT: Buffer overflow
```

**Why It's Dangerous**:
- Overwrites adjacent stack/heap memory
- Can overwrite return addresses (stack smashing)
- Enables arbitrary code execution

**Fix**:
```c
char dest[10];
strncpy(dest, src, sizeof(dest) - 1);
dest[sizeof(dest) - 1] = '\0';
```

---

### cpp/unbounded-write (CWE-787)

**Vulnerability**: Writing to a buffer without checking bounds.

**How CodeQL Detects It**:
- Identifies writes where size is user-controlled
- Checks for missing bounds validation
- Tracks data flow from input sources to write operations

**Vulnerable Code**:
```c
void copy(char *dest, char *src, size_t n) {
    // No check that n <= dest_size
    memcpy(dest, src, n);  // ALERT: Unbounded write
}
```

**Why It's Dangerous**:
- Attacker controls write size
- Can write arbitrary amounts of data
- Heap/stack corruption

**Fix**:
```c
void copy(char *dest, size_t dest_size, char *src, size_t n) {
    if (n > dest_size) n = dest_size;
    memcpy(dest, src, n);
}
```

---

### cpp/no-space-for-terminator (CWE-131)

**Vulnerability**: Buffer allocated without space for null terminator.

**How CodeQL Detects It**:
- Tracks string length calculations (strlen)
- Checks if allocation size accounts for +1 for null terminator
- Analyzes strncpy/snprintf where size equals buffer size exactly

**Vulnerable Code**:
```c
char *copy = malloc(strlen(input));  // ALERT: No space for '\0'
strcpy(copy, input);
```

**Why It's Dangerous**:
- String operations write past buffer end
- Null terminator overwrites adjacent memory
- Unterminated strings cause subsequent overreads

**Fix**:
```c
char *copy = malloc(strlen(input) + 1);  // +1 for null terminator
strcpy(copy, input);
```

---

### cpp/overrunning-write (CWE-787)

**Vulnerability**: Write operation exceeds buffer capacity.

**How CodeQL Detects It**:
- Computes buffer size from allocation
- Analyzes write offset and size
- Detects when offset + write_size > buffer_size

**Vulnerable Code**:
```c
int arr[10];
for (int i = 0; i <= 10; i++) {  // Should be i < 10
    arr[i] = 0;  // ALERT: Off-by-one write at i=10
}
```

---

### cpp/overrunning-read (CWE-125)

**Vulnerability**: Reading beyond buffer bounds.

**How CodeQL Detects It**:
- Similar to overrunning-write but for read operations
- Tracks array indexing and pointer arithmetic
- Analyzes loop bounds vs array sizes

**Vulnerable Code**:
```c
char buffer[100];
read(fd, buffer, 100);
for (int i = 0; i <= 100; i++) {
    process(buffer[i]);  // ALERT: Out-of-bounds read at i=100
}
```

---

### cpp/unclear-array-index-validation (CWE-129)

**Vulnerability**: Array index from untrusted source without proper validation.

**How CodeQL Detects It**:
- Tracks user input to array index operations
- Checks if index is validated against array bounds
- Considers both upper and lower bound checks

**Vulnerable Code**:
```c
int array[100];
int index = atoi(user_input);
return array[index];  // ALERT: Unvalidated index
```

**Fix**:
```c
int index = atoi(user_input);
if (index >= 0 && index < 100) {
    return array[index];
}
```

---

## Injection Vulnerabilities

### cpp/sql-injection (CWE-89)

**Vulnerability**: User input concatenated into SQL queries.

**CodeQL Discovery Flow**:
```
┌────────────────────────────────────────────────────────────────────────┐
│                      SQL INJECTION DETECTION                           │
├────────────────────────────────────────────────────────────────────────┤
│                                                                        │
│  STEP 1: Define Taint Sources (Untrusted Input)                        │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │ argv[i]                 → Command line arguments                 │  │
│  │ getenv("VAR")           → Environment variables                  │  │
│  │ scanf("%s", buf)        → Standard input                         │  │
│  │ fgets(buf, n, stdin)    → Standard input                         │  │
│  │ read(fd, buf, n)        → File/socket input                      │  │
│  │ recv(sock, buf, n, 0)   → Network input                          │  │
│  │ Mark: These values are TAINTED                                   │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                              │                                         │
│                              ▼                                         │
│  STEP 2: Track Taint Propagation                                       │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │ y = x;                  → y inherits taint from x                │  │
│  │ sprintf(buf, "%s", x);  → buf becomes tainted                    │  │
│  │ strcat(buf, x);         → buf becomes tainted                    │  │
│  │ func(x) returns y;      → y may be tainted (interprocedural)     │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                              │                                         │
│                              ▼                                         │
│  STEP 3: Define SQL Sinks                                              │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │ mysql_query(conn, query)           → query is sink               │  │
│  │ sqlite3_exec(db, query, ...)       → query is sink               │  │
│  │ PQexec(conn, query)                → query is sink (PostgreSQL)  │  │
│  │ ODBC: SQLExecDirect(stmt, query)   → query is sink               │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                              │                                         │
│                              ▼                                         │
│  STEP 4: Path Existence Check                                          │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │ Query: Is there a data flow path from any SOURCE to any SINK?    │  │
│  │ Check: Are there sanitizers on the path?                         │  │
│  │        mysql_real_escape_string() → Blocks taint flow            │  │
│  │        Parameterized query        → Not flagged                  │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                              │                                         │
│                              ▼                                         │
│  STEP 5: Report Injection                                              │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │ ALERT: SQL injection vulnerability                               │  │
│  │ CodeFlow: SOURCE → [propagation steps] → SINK                    │  │
│  │ Example: argv[1] → sprintf(query,...) → mysql_query(query)       │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                                                                        │
└────────────────────────────────────────────────────────────────────────┘
```

**How CodeQL Detects It**:
- Identifies SQL execution functions (mysql_query, sqlite3_exec, etc.)
- Taint-tracks from input sources (argv, scanf, fgets, network)
- Detects string concatenation/formatting into queries

**Vulnerable Code**:
```c
char query[256];
sprintf(query, "SELECT * FROM users WHERE id = '%s'", user_input);
mysql_query(conn, query);  // ALERT: SQL injection
```

**Why It's Dangerous**:
- Attacker can modify query logic
- Data exfiltration, authentication bypass
- Database modification or deletion

**Fix**:
```c
MYSQL_STMT *stmt = mysql_stmt_init(conn);
mysql_stmt_prepare(stmt, "SELECT * FROM users WHERE id = ?", ...);
mysql_stmt_bind_param(stmt, ...);  // Bind user_input safely
mysql_stmt_execute(stmt);
```

---

### cpp/command-line-injection (CWE-78)

**Vulnerability**: User input passed to command execution functions.

**CodeQL Discovery Flow**:
```
┌────────────────────────────────────────────────────────────────────────┐
│                   COMMAND INJECTION DETECTION                          │
├────────────────────────────────────────────────────────────────────────┤
│                                                                        │
│  STEP 1: Define Taint Sources                                          │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │ Same as SQL injection: argv, getenv, scanf, fgets, network...    │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                              │                                         │
│                              ▼                                         │
│  STEP 2: Define Command Execution Sinks                                │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │ system(cmd)              → Shell command execution               │  │
│  │ popen(cmd, mode)         → Shell command with pipe               │  │
│  │ execl("/bin/sh", "sh", "-c", cmd)  → Shell via exec              │  │
│  │ CreateProcess(...cmd...) → Windows command (with shell)          │  │
│  │ ShellExecute(...)        → Windows shell execution               │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                              │                                         │
│                              ▼                                         │
│  STEP 3: Shell Metacharacter Analysis                                  │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │ Dangerous characters: ; | & $ ` ( ) { } < > \n                   │  │
│  │ Check: Is tainted data passed to shell sink?                     │  │
│  │ Sanitizer: Proper escaping of metacharacters blocks flow         │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                              │                                         │
│                              ▼                                         │
│  STEP 4: Distinguish Safe exec* Patterns                               │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │ execl("/usr/bin/ping", "ping", host, NULL)                       │  │
│  │ → Arguments passed directly, NO shell interpretation             │  │
│  │ → NOT flagged (unless host contains null bytes)                  │  │
│  │                                                                  │  │
│  │ system("ping " + host)                                           │  │
│  │ → Shell interprets metacharacters                                │  │
│  │ → FLAGGED                                                        │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                              │                                         │
│                              ▼                                         │
│  STEP 5: Report                                                        │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │ ALERT: Command injection vulnerability                           │  │
│  │ CodeFlow: Input source → string building → system()/popen()      │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                                                                        │
└────────────────────────────────────────────────────────────────────────┘
```

**How CodeQL Detects It**:
- Identifies command execution: system(), popen(), exec*()
- Taint-tracks user input to these sinks
- Checks for shell metacharacter sanitization

**Vulnerable Code**:
```c
char cmd[256];
sprintf(cmd, "ping %s", user_host);
system(cmd);  // ALERT: Command injection
```

**Attack Example**:
```
user_host = "localhost; rm -rf /"
cmd = "ping localhost; rm -rf /"
```

**Fix**:
```c
// Option 1: Validate input
if (!is_valid_hostname(user_host)) return;

// Option 2: Use exec* without shell
execlp("ping", "ping", user_host, NULL);

// Option 3: Escape shell metacharacters
char *escaped = escape_shell(user_host);
```

---

### cpp/tainted-format-string (CWE-134)

**Vulnerability**: User input used as format string.

**How CodeQL Detects It**:
- Identifies format functions: printf, sprintf, syslog, etc.
- Checks if format string argument is user-controlled
- Tracks taint from input sources

**Vulnerable Code**:
```c
printf(user_input);  // ALERT: Format string vulnerability
```

**Attack Example**:
```
user_input = "%x%x%x%x%n"  // Read stack, write to memory
```

**Why It's Dangerous**:
- `%x` reads stack memory (info leak)
- `%n` writes to memory (arbitrary write)
- Can achieve code execution

**Fix**:
```c
printf("%s", user_input);  // user_input is now data, not format
```

---

### cpp/path-injection (CWE-22)

**Vulnerability**: User input used in file path without sanitization.

**How CodeQL Detects It**:
- Identifies file operations: fopen, open, stat, access
- Taint-tracks user input to file path arguments
- Checks for path traversal patterns (../)

**Vulnerable Code**:
```c
char path[256];
sprintf(path, "/var/data/%s", user_filename);
FILE *f = fopen(path, "r");  // ALERT: Path injection
```

**Attack Example**:
```
user_filename = "../../../etc/passwd"
path = "/var/data/../../../etc/passwd" = "/etc/passwd"
```

**Fix**:
```c
// Validate: no path separators, no ..
if (strchr(user_filename, '/') || strstr(user_filename, "..")) {
    return ERROR;
}
// Or use realpath() and verify prefix
char *real = realpath(path, NULL);
if (strncmp(real, "/var/data/", 10) != 0) return ERROR;
```

---

### cpp/xml-external-entity (CWE-611)

**Vulnerability**: XML parser processes external entities from untrusted XML.

**How CodeQL Detects It**:
- Identifies XML parsing libraries (libxml2, expat, xerces)
- Checks if external entity processing is enabled
- Taint-tracks untrusted XML input

**Vulnerable Code**:
```c
xmlDocPtr doc = xmlReadMemory(user_xml, size, NULL, NULL, 0);
// Default options may enable external entities
```

**Attack (XXE)**:
```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<data>&xxe;</data>
```

**Fix**:
```c
int options = XML_PARSE_NOENT | XML_PARSE_DTDLOAD;
// Disable: XML_PARSE_NOENT actually expands entities!
// Use: XML_PARSE_NONET to disable network access
xmlDocPtr doc = xmlReadMemory(user_xml, size, NULL, NULL, 
    XML_PARSE_NONET | XML_PARSE_NOENT);
```

---

## Integer Vulnerabilities

### cpp/integer-overflow (CWE-190)

**Vulnerability**: Arithmetic operation overflows integer bounds.

**How CodeQL Detects It**:
- Analyzes arithmetic operations on integers
- Tracks value ranges through the program
- Identifies operations that can exceed INT_MAX or underflow

**Vulnerable Code**:
```c
int allocate(int count, int size) {
    int total = count * size;  // ALERT: May overflow
    return malloc(total);      // Allocates less than expected
}
```

**Attack Example**:
```c
allocate(1073741824, 4);  // 2^30 * 4 = 2^32 = 0 (overflow)
// malloc(0) returns valid pointer, but buffer is tiny
```

**Fix**:
```c
size_t total;
if (__builtin_mul_overflow(count, size, &total)) {
    return NULL;  // Overflow detected
}
return malloc(total);
```

---

### cpp/unsigned-difference-expression-compared-zero (CWE-191)

**Vulnerability**: Subtracting from unsigned value and comparing to zero.

**How CodeQL Detects It**:
- Identifies subtraction on unsigned integers
- Checks if result is compared to zero
- Flags cases where underflow could occur

**Vulnerable Code**:
```c
size_t length = get_length();
if (length - 5 > 0) {  // ALERT: If length < 5, wraps to huge number
    process(length - 5);
}
```

**Why It's Dangerous**:
- Unsigned underflow wraps to large positive value
- Condition is unexpectedly true
- Can cause buffer overflows

**Fix**:
```c
if (length > 5) {  // Compare before subtraction
    process(length - 5);
}
```

---

### cpp/tainted-allocation-size (CWE-789)

**Vulnerability**: User input controls memory allocation size.

**How CodeQL Detects It**:
- Taint-tracks from input sources to malloc/calloc/realloc size parameter
- Checks for validation of size before allocation

**Vulnerable Code**:
```c
size_t size = atoi(user_input);
char *buf = malloc(size);  // ALERT: Tainted allocation size
```

**Why It's Dangerous**:
- Attacker can cause huge allocations (DoS)
- Attacker can cause zero/small allocations then overflow
- Integer overflow in size calculation

**Fix**:
```c
size_t size = atoi(user_input);
if (size == 0 || size > MAX_ALLOWED_SIZE) {
    return ERROR;
}
char *buf = malloc(size);
```

---

### cpp/bad-addition-overflow-check (CWE-190)

**Vulnerability**: Incorrect overflow check pattern.

**How CodeQL Detects It**:
- Identifies common incorrect overflow check patterns
- Checks like `if (a + b < a)` after the addition

**Vulnerable Code**:
```c
int result = a + b;
if (result < a) {  // ALERT: Check is after overflow already happened
    return ERROR;  // Undefined behavior already occurred
}
```

**Fix**:
```c
if (a > INT_MAX - b) {  // Check before addition
    return ERROR;
}
int result = a + b;
```

---

## Cryptographic Issues

### cpp/weak-cryptographic-algorithm (CWE-327)

**Vulnerability**: Use of broken or weak cryptographic algorithms.

**How CodeQL Detects It**:
- Identifies calls to weak crypto functions
- Matches function names: MD5, SHA1, DES, RC4, etc.
- Checks crypto library usage patterns

**Weak Algorithms**:
| Algorithm | Issue | Replacement |
|-----------|-------|-------------|
| MD5 | Collision attacks | SHA-256, SHA-3 |
| SHA-1 | Collision attacks | SHA-256, SHA-3 |
| DES | 56-bit key too small | AES-256 |
| 3DES | Slow, 112-bit effective | AES-256 |
| RC4 | Biased output | AES-GCM, ChaCha20 |
| Blowfish | 64-bit block size | AES-256 |

**Vulnerable Code**:
```c
MD5_CTX ctx;
MD5_Init(&ctx);
MD5_Update(&ctx, password, strlen(password));
MD5_Final(hash, &ctx);  // ALERT: MD5 is weak
```

**Fix**:
```c
EVP_MD_CTX *ctx = EVP_MD_CTX_new();
EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
EVP_DigestUpdate(ctx, password, strlen(password));
EVP_DigestFinal_ex(ctx, hash, NULL);
```

---

### cpp/cleartext-storage-file (CWE-312)

**Vulnerability**: Sensitive data written to file without encryption.

**How CodeQL Detects It**:
- Identifies sensitive data (passwords, tokens, keys)
- Tracks flow to file write operations
- Checks if encryption is applied before writing

**Vulnerable Code**:
```c
FILE *f = fopen("config.txt", "w");
fprintf(f, "password=%s\n", password);  // ALERT: Cleartext storage
fclose(f);
```

---

### cpp/cleartext-transmission (CWE-319)

**Vulnerability**: Sensitive data sent over network without encryption.

**How CodeQL Detects It**:
- Identifies sensitive data
- Tracks to network send functions (send, write to socket)
- Checks if TLS/encryption is used

**Vulnerable Code**:
```c
int sock = socket(AF_INET, SOCK_STREAM, 0);
connect(sock, ...);
send(sock, password, strlen(password), 0);  // ALERT: Cleartext transmission
```

---

### cpp/hardcoded-credentials (CWE-798)

**Vulnerability**: Passwords or keys hardcoded in source.

**How CodeQL Detects It**:
- Pattern matches variable names: password, secret, key, token
- Checks for string literal assignments
- Identifies comparison with hardcoded strings

**Vulnerable Code**:
```c
const char *password = "admin123";  // ALERT: Hardcoded credential
if (strcmp(input, "secretpassword") == 0) { ... }  // ALERT
```

---

## Resource Management

### cpp/resource-leak (CWE-772)

**Vulnerability**: Allocated resource not freed on all execution paths.

**How CodeQL Detects It**:
- Tracks resource acquisition (malloc, fopen, socket)
- Analyzes all execution paths through function
- Identifies paths where resource is not released

**Vulnerable Code**:
```c
void process(char *filename) {
    FILE *f = fopen(filename, "r");
    if (some_condition) {
        return;  // ALERT: f not closed on this path
    }
    fclose(f);
}
```

**Fix**:
```c
void process(char *filename) {
    FILE *f = fopen(filename, "r");
    if (some_condition) {
        fclose(f);  // Close before return
        return;
    }
    fclose(f);
}
```

---

### cpp/file-descriptor-leak

**Vulnerability**: File descriptor not closed.

**How CodeQL Detects It**:
- Tracks open(), socket(), accept() return values
- Checks for close() on all paths
- Considers error handling paths

---

## Dangerous Functions

### cpp/potentially-dangerous-function (CWE-676)

**Vulnerability**: Use of functions known to be dangerous.

**Dangerous Functions**:

| Function | Risk | Safe Alternative |
|----------|------|------------------|
| `gets()` | No bounds checking | `fgets()` |
| `strcpy()` | No bounds checking | `strncpy()`, `strlcpy()` |
| `strcat()` | No bounds checking | `strncat()`, `strlcat()` |
| `sprintf()` | No bounds checking | `snprintf()` |
| `scanf("%s")` | No bounds checking | `scanf("%Ns")` with width |
| `mktemp()` | Race condition | `mkstemp()` |
| `tmpnam()` | Race condition | `tmpfile()` |

**Vulnerable Code**:
```c
char buf[100];
gets(buf);  // ALERT: Never use gets()
```

**Fix**:
```c
char buf[100];
if (fgets(buf, sizeof(buf), stdin)) {
    buf[strcspn(buf, "\n")] = 0;  // Remove newline
}
```

---

### cpp/dangerous-cin (CWE-676)

**Vulnerability**: Unbounded input with `cin >>` into fixed buffer.

**Vulnerable Code (C++)**:
```cpp
char buffer[100];
cin >> buffer;  // ALERT: No size limit
```

**Fix**:
```cpp
string buffer;
cin >> buffer;  // std::string grows as needed

// Or with width limit:
char buffer[100];
cin >> setw(100) >> buffer;
```

---

## Null Pointer Issues

### cpp/null-dereference (CWE-476)

**Vulnerability**: Dereferencing a pointer that may be NULL.

**How CodeQL Detects It**:
- Tracks pointer values through assignments
- Identifies sources of NULL (malloc failure, function returns)
- Checks if NULL is dereferenced without prior check

**Vulnerable Code**:
```c
char *ptr = malloc(100);
// Missing NULL check
strcpy(ptr, data);  // ALERT: ptr may be NULL
```

**Fix**:
```c
char *ptr = malloc(100);
if (ptr == NULL) {
    return ERROR;
}
strcpy(ptr, data);
```

---

### cpp/redundant-null-check-simple

**Vulnerability**: Pointer is dereferenced before NULL check.

**Vulnerable Code**:
```c
int len = strlen(str);  // Dereferences str
if (str == NULL) {      // ALERT: Check after dereference
    return;
}
```

---

## Race Conditions

### cpp/toctou-race-condition (CWE-367)

**Vulnerability**: Time-of-check to time-of-use race condition.

**How CodeQL Detects It**:
- Identifies check-then-use patterns on files
- Checks access()/stat() followed by open()
- Flags when file could be modified between check and use

**Vulnerable Code**:
```c
if (access(filename, R_OK) == 0) {  // Check
    // Attacker can replace file here!
    FILE *f = fopen(filename, "r");  // Use - ALERT: TOCTOU
}
```

**Why It's Dangerous**:
- Attacker can swap file between check and use
- Symlink attacks: replace regular file with symlink
- Can bypass access controls

**Fix**:
```c
// Open first, then check permissions on open handle
int fd = open(filename, O_RDONLY);
if (fd >= 0) {
    struct stat st;
    if (fstat(fd, &st) == 0 && /* check st */) {
        // Use fd
    }
    close(fd);
}
```

---

## Information Disclosure

### cpp/world-readable-file-creation (CWE-732)

**Vulnerability**: File created with excessive permissions.

**How CodeQL Detects It**:
- Checks mode argument to open(), creat(), chmod()
- Flags world-readable/writable permissions (0666, 0777)

**Vulnerable Code**:
```c
int fd = open("secrets.txt", O_CREAT | O_WRONLY, 0666);  // ALERT
```

**Fix**:
```c
int fd = open("secrets.txt", O_CREAT | O_WRONLY, 0600);  // Owner only
```

---

### cpp/exposure-of-sensitive-data (CWE-200)

**Vulnerability**: Sensitive data exposed through logging or errors.

**How CodeQL Detects It**:
- Identifies sensitive variables (password, secret, key)
- Tracks flow to logging functions (printf, syslog, fprintf(stderr))

**Vulnerable Code**:
```c
syslog(LOG_DEBUG, "Auth failed for user %s with password %s", 
       user, password);  // ALERT: Password in logs
```

---

## Summary: Top 10 C/C++ Vulnerabilities

| Priority | Vulnerability | CWE | Impact |
|----------|--------------|-----|--------|
| 1 | Buffer Overflow | CWE-120 | Code execution |
| 2 | Command Injection | CWE-78 | Code execution |
| 3 | Use After Free | CWE-416 | Code execution |
| 4 | Format String | CWE-134 | Code execution |
| 5 | SQL Injection | CWE-89 | Data breach |
| 6 | Integer Overflow | CWE-190 | Various |
| 7 | Path Traversal | CWE-22 | Data access |
| 8 | Null Dereference | CWE-476 | Crash/DoS |
| 9 | Double Free | CWE-415 | Code execution |
| 10 | Resource Leak | CWE-772 | DoS |

---

## References

- [CodeQL C/C++ Queries](https://github.com/github/codeql/tree/main/cpp/ql/src)
- [CWE - Common Weakness Enumeration](https://cwe.mitre.org/)
- [CERT C Coding Standard](https://wiki.sei.cmu.edu/confluence/display/c)
- [CERT C++ Coding Standard](https://wiki.sei.cmu.edu/confluence/display/cplusplus)
