# SAST Analysis of OWASP Juice Shop

## 1. Methodology

### Tool and Configuration

For the SAST part of this project we used Semgrep version 1.156.0. We picked Semgrep because it is free, open-source, and works well with JavaScript and TypeScript which is what Juice Shop is built with. It does not need you to build or run the application — it just reads through the code files and looks for patterns that match known vulnerabilities.

We used the `p/javascript` ruleset which comes with Semgrep. This is a collection of security rules made for JavaScript and Node.js apps. It covers things like SQL injection, code injection, hardcoded secrets, and unsafe use of Express.js APIs.

### What We Scanned

We focused the scan on two folders:

- **routes/** — This is where all the HTTP request handling code lives. There are 61 TypeScript files in here covering login, search, file serving, user profiles, and everything else. Since this is where user input gets processed, it is the most likely place to find injection vulnerabilities.
- **lib/** — This has the utility code and security-related functions, including JWT authentication, input sanitisation, and crypto stuff.

We did not scan the whole repository because that would include test files, frontend code, and other things that would just add noise. The point was to focus on the server-side code that actually handles user input.

### How We Ran It

We ran two scans from the juice-shop directory:

```bash
semgrep scan --config "p/javascript" routes/
semgrep scan --config "p/javascript" lib/
```

The whole thing took about 10 seconds and covered 85 files in total (61 in routes, 24 in lib). We also ran it with `--json` output to get structured data for analysis.

## 2. Results Overview

Semgrep found 9 issues in total:

| Severity | Count | What it found |
|----------|-------|---------------|
| ERROR (High) | 3 | SQL Injection (2), Code Injection (1) |
| WARNING (Medium) | 6 | Path Traversal (4), Open Redirect (1), Hardcoded Credentials (1) |

All 9 findings were flagged as "Blocking" which means Semgrep considers them real security issues, not just informational. We picked the three ERROR-level findings for deeper analysis since those are the most serious ones.

The remaining 6 WARNING findings were: four cases of res.sendFile() being used with user input (fileServer.ts, keyServer.ts, logfileServer.ts, quarantineServer.ts), one open redirect in redirect.ts, and one hardcoded JWT key in insecurity.ts.

## 3. Deep Analysis of Top 3 Findings

### Finding 1: SQL Injection in Login and Search (CWE-89)

**Rule:** express-sequelize-injection | **Severity:** ERROR | **Files:** login.ts:34, search.ts:23

Semgrep caught two places where user input gets put straight into SQL queries using Sequelize's raw query method. In login.ts the email from the login form goes right in:

```javascript
models.sequelize.query(`SELECT * FROM Users WHERE email = '${req.body.email}'...`)
```

And in search.ts the same thing happens with the search box input:

```javascript
models.sequelize.query(`SELECT * FROM Products WHERE ((name LIKE '%${criteria}%'...`)
```

**Did we confirm it?** Yes. We exploited both of these during manual testing. For login.ts, entering `bender@juice-sh.op'--` as the email let us log in as Bender without a password. For search.ts, injecting `')) --` let us find deleted products that were supposed to be hidden. Both are definitely real and exploitable.

**Verdict:** True positive. Maps to A03:2021 - Injection and is in the CWE Top 25. The fix would be to use Sequelize's ORM methods or parameterised queries instead of building SQL strings by hand.

### Finding 2: Code Injection via eval() in User Profile (CWE-95)

**Rule:** code-string-concat | **Severity:** ERROR | **File:** userProfile.ts:62

Semgrep found an eval() call that processes user-controlled data. In the user profile rendering code, if a username matches the pattern `#{...}`, whatever is inside the braces gets passed to eval():

```javascript
username = eval(code)
```

This is Server-Side Template Injection (SSTI). If you set your username to something like `#{7*7}`, the server actually executes that as JavaScript. An attacker could potentially read server files, access environment variables, or run system commands.

**Did we confirm it?** We confirmed the code path exists by reading the source code. The vulnerability is real — any user can change their username through the profile page to include a #{...} payload, and it will be executed on the server when the profile renders.

**Verdict:** True positive and very dangerous. Maps to A03:2021 - Injection, specifically CWE-95 (Eval Injection). The fix is obvious — get rid of eval() and use a proper templating engine.

### Finding 3: Hardcoded JWT Secret (CWE-798)

**Rule:** hardcoded-jwt-secret | **Severity:** WARNING | **File:** insecurity.ts:56

Semgrep flagged the JWT signing code because the private key is bundled with the application:

```javascript
export const authorize = (user = {}) => jwt.sign(user, privateKey, { expiresIn: '6h', algorithm: 'RS256' })
```

The app uses RS256 which is good (asymmetric signing), but the private key file is sitting right there in the source code. Anyone who has access to the repo can grab it and forge valid JWT tokens for any user.

**Did we confirm it?** During testing we decoded JWT tokens and found they contain user data including password hashes. Since the private key is available in the code, an attacker could create fake tokens and impersonate any user, including admins.

**Verdict:** True positive. Maps to A02:2021 - Cryptographic Failures and CWE-798. In a real app, signing keys should come from environment variables or a key management service, not from the source code.

## 4. False Positives and Limitations

Out of the 9 findings, we did not find any false positives. Everything Semgrep flagged was a genuine security issue. That said, Juice Shop is intentionally vulnerable so this is not surprising — in a real application you would expect more false positives.

The four path traversal warnings (CWE-73) are real but we did not analyse them in depth because they all follow the same pattern: res.sendFile() with user input. Looking at one covers all four.

One important thing we noticed is what Semgrep did NOT find. During manual testing we discovered a broken authentication flaw in the change password function (CWE-620) where you can change a password without knowing the current one. Semgrep missed this because it is a logic bug — the code is syntactically correct, it just behaves wrong. SAST tools are good at finding injection and configuration problems, but they struggle with logic flaws. That is why you need both SAST and DAST (plus manual testing) to get proper coverage.

## References

[1] Semgrep, "Semgrep: Lightweight static analysis for many languages," 2024. [Online]. Available: https://semgrep.dev/

[2] OWASP, "A03:2021 - Injection," OWASP Top 10, 2021. [Online]. Available: https://owasp.org/Top10/A03_2021-Injection/

[3] OWASP, "A02:2021 - Cryptographic Failures," OWASP Top 10, 2021. [Online]. Available: https://owasp.org/Top10/A02_2021-Cryptographic_Failures/

[4] MITRE, "CWE-89: SQL Injection." [Online]. Available: https://cwe.mitre.org/data/definitions/89.html

[5] MITRE, "CWE-95: Eval Injection." [Online]. Available: https://cwe.mitre.org/data/definitions/95.html

[6] MITRE, "CWE-798: Use of Hard-coded Credentials." [Online]. Available: https://cwe.mitre.org/data/definitions/798.html
