# Security

## Reporting a weakness

Please tell us privately before making it public.

1. Open the **Security** tab of this repository.
2. Choose **Report a vulnerability**.
3. Say what you found, how to reproduce it, and what it lets someone do.

We aim to answer within three working days and will tell you when a fix is released.
Please do not test against a deployment that holds someone else's alerts.

## What is checked on every change

- Every automated test, including who may call each address in the application
  (`tests/test_hardening.py` reads the routes from the application itself).
- The container image is built, and the build runs the tests: an image cannot
  be made from a change that breaks one.
- Known vulnerabilities in the libraries (`pip-audit`).
- Code scanning (CodeQL) for Python and JavaScript.

## What is in place

Sign-in with roles, single sign-on (OpenID Connect), a second factor for
password accounts, a lockout on guessing, a token on every form, a page policy
that runs only our own scripts, a key for each customer on the way in, an
audit log chained by hash, and no response action without a named analyst.
`/security` on any deployment says the same in plain words.

## What is not done yet

An independent penetration test. It is planned before the first customer pilot.
