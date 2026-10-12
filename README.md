# Blind SQL Injection Against DVWA — Low, Medium & High Security

A hands-on exploration of time-based blind SQL injection against the "SQL Injection (Blind)"
module of **Damn Vulnerable Web App (DVWA)**, across all three security levels. Each level
required diagnosing a *different* server-side defense and adapting the exploit accordingly,
rather than reusing one payload everywhere.

> ⚠️ **Scope & disclaimer**
> This project was carried out entirely against DVWA, a deliberately vulnerable application
> designed for security training, running in an isolated local VM (Kali Linux + VirtualBox,
> target `10.0.2.5`). No external, production, or third-party systems were targeted. All
> techniques here are for authorized security education only.

---

## Objective

To understand and practically demonstrate:
1. How time-based blind SQL injection works when an application gives no visible error or
   content difference, only a timing side-channel.
2. How the same underlying vulnerability class is progressively mitigated across DVWA's
   Low → Medium → High security settings, and what specifically breaks a naive exploit at
   each step.
3. How to debug a non-working exploit methodically — by reading server-side source, forming
   a hypothesis, testing it in isolation, and confirming before moving on — rather than
   guessing payloads.

## Environment

| Component       | Detail                                   |
|------------------|-------------------------------------------|
| Target           | DVWA v1.x, PHP 5.2.4, MySQL ≥ 5.0.12, Apache 2.2.8 on Ubuntu 8.04 (Hardy Heron) |
| Attack host      | Kali Linux 2026.2 (VirtualBox)            |
| Tools            | `sqlmap` (initial reconnaissance), Python 3 + `requests` (custom exploit scripts) |

## Methodology

### 1. Reconnaissance with sqlmap
Before writing any custom code, `sqlmap` was used to confirm the injection point existed and
fingerprint the backend:

```bash
sqlmap -u "http://10.0.2.5/dvwa/vulnerabilities/sqli_blind/?id=1&Submit=Submit#" \
  --cookie="PHPSESSID=<session>;security=low" --banner -v 3
```

This confirmed:
- A **time-based blind** injection point on the `id` parameter (`SLEEP()`-based).
- At low security, a **TIME-BASED Blind** injection point was also available.
- Backend: MySQL `5.0.51a-3ubuntu5`, PHP 5.2.4, Apache 2.2.8 on Ubuntu 8.04.

sqlmap's own successful payloads (unquoted, e.g. `id=1 AND (SELECT ... SLEEP(5))`) were used
as a reference point when debugging the custom script later.

### 2. Custom exploit script (why not just use sqlmap?)
The goal of this project was to **understand the mechanics**, not just run a tool. A Python
script was built from scratch to perform character-by-character blind extraction using the
classic boolean/time oracle pattern:

```
IF(SUBSTRING((<subquery>), <position>, 1) = <candidate char>, SLEEP(5), 0)
```

For each character position, every candidate in a defined charset is tried; a response time
over a threshold (>4s) is treated as "true," confirming that character, and the script moves
to the next position. This was used to extract, in order: the MySQL version, the current
database name, table names, column names, and finally user credentials from the `users` table.

### 3. Debugging across security levels
Each DVWA security level broke the script in a different way, and each required reading the
actual page source (`view-source` via DVWA's built-in source viewer) rather than assuming
standard DVWA behavior, since implementation details varied slightly on this build.

#### 🟢 Low security — `blind_sqli_low.py`
- Vulnerable query: `WHERE user_id = '$id'` — no sanitization, no escaping.
- Requires an **authenticated session with DVWA's security level actually set server-side**
  (DVWA stores this in `$_SESSION`, not in a cookie value — an early mistake was assuming a
  `security=low` cookie alone was sufficient; it was not).
- Payload: standard quoted blind injection.
  ```python
  payload = f"1' AND IF(SUBSTRING(({sql_query}),{i},1)='{char}',SLEEP(5),0)#"
  ```
- Result: full extraction worked — version, database name, table names, column names, and
  the `admin` user's credentials were all successfully recovered.

#### 🟡 Medium security — `blind_sqli_medium.py`
- Vulnerable query: `WHERE user_id = $id` (unquoted), input passed through
  `mysqli_real_escape_string()`.
- **First bug found:** escaping applies to *every* quote in the submitted value — not just an
  injected leading quote, but also the quotes used for the character comparison itself
  (`='{char}'`). The fix was to drop quotes entirely and compare against a **hex-encoded**
  literal instead, since MySQL treats `0x61` identically to `'a'` without needing any quote
  characters:
  ```python
  hex_char = char.encode().hex()
  payload = f"1 AND IF(SUBSTRING(({sql_query}),{i},1)=0x{hex_char},SLEEP(5),0)#"
  ```
- **Second bug found:** an incorrect assumption that medium security switched the form to
  `POST`. Reading the actual page source confirmed this build still reads `id` via `$_GET`
  at medium — only the escaping changed, not the HTTP method. Reverting to `GET` fixed it.
- Result: full extraction worked once both issues were corrected.

#### 🔴 High security — not exploitable via this parameter
- Vulnerable query: `WHERE user_id = '$id'`, but gated behind a strict **`is_numeric($id)`**
  check before the query ever executes:
  ```php
  if (is_numeric($id)) {
      $getid = "SELECT first_name, last_name FROM users WHERE user_id = '$id'";
  ```
- `is_numeric()` only accepts a string that is *entirely* a valid number (digits, one
  optional decimal point, optional sign/exponent). No SQL keyword, space, or quote can exist
  inside a string that also satisfies this check — so the vulnerable branch simply never runs
  for any injection payload.
- This was **confirmed empirically**, not assumed:
  - `?id=1&Submit=Submit` → normal result (baseline works).
  - `?id=1 AND SLEEP(5)&Submit=Submit` → instant response, no delay (rejected).
  - `?id=0x31&Submit=Submit` → instant response, no delay (the legacy PHP `is_numeric()`
    hex-string quirk, present in some old PHP 5.x builds, does **not** exist in this one).
- **Conclusion:** on this specific endpoint and build, type validation (not just character
  escaping) fully closes this injection vector. This is the intended lesson of DVWA's high
  setting for this module: it demonstrates the difference between *sanitizing characters*
  (medium — bypassable) and *validating type* (high — not bypassable via this field).

## Results Summary

| Level  | Vulnerable? | Defense present                  | Bypass technique                          |
|--------|-------------|-----------------------------------|--------------------------------------------|
| Low    | ✅ Yes      | None                               | Direct quoted time-based blind injection   |
| Medium | ✅ Yes      | Quote escaping only                | Hex-encoded literals avoid quotes entirely |
| High   | ❌ No       | `is_numeric()` type validation     | None found — structurally not bypassable via `id` |

## Key Takeaways

- **Escaping characters ≠ validating input.** Medium security's `mysqli_real_escape_string()`
  only neutralizes quote characters; it does nothing to stop an unquoted numeric-context
  injection, and can even be fully sidestepped using hex-literal comparisons that never need
  a quote in the first place.
- **Type validation is a much stronger control than character filtering**, when applied
  correctly. `is_numeric()` at high security closes the door because it constrains the
  *entire shape* of the input, not just specific characters within it.
- **Don't assume — read the source.** Several early debugging dead ends in this project came
  from assuming standard/"textbook" DVWA behavior (e.g. a form switching to POST at medium)
  instead of checking this specific build's actual PHP source via DVWA's built-in source
  viewer. Confirming behavior empirically (timing tests, baseline checks) before writing more
  code saved significant time once adopted as a habit.

## Repository Contents

```
.
├── README.md              # this file
├── blind_sqli_low.py      # exploit for DVWA Low security
└── blind_sqli_medium.py   # exploit for DVWA Medium security
```

High security is intentionally **not** included as a working exploit script, since no viable
injection point was found through `id` — see the High Security section above for the full
reasoning and evidence behind that conclusion.

## How to Run

1. Stand up DVWA in an isolated lab environment (e.g. the official DVWA Docker image or a
   Metasploitable-style VM). Do not point this at any system you do not own or have explicit
   permission to test.
2. Update the `DVWA_USER`, `DVWA_PASS`, and `base_url` values at the top of each script to
   match your environment.
3. Run with Python 3:
   ```bash
   python3 blind_sqli_low.py
   python3 blind_sqli_medium.py
   ```
4. Each script logs in, sets the relevant DVWA security level server-side, and extracts the
   MySQL version, database name, table names, column names, and a sample of user credentials
   using pure time-based blind SQL injection.

## Requirements

```bash
pip install requests
```
