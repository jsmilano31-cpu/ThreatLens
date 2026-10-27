# ThreatLens v1

A database-free Flask login and URL investigation workspace. `scanner.py` remains the shared core for the website and command line. IP scanning is not implemented.

## Run locally (PowerShell)

```powershell
python -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt
$env:THREATLENS_USERNAME = 'analyst'
$env:THREATLENS_PASSWORD = 'choose-a-long-unique-password'
# Optional: real vendor analysis; otherwise local rules only
$env:VT_API_KEY = 'your-virustotal-api-key'
.venv\Scripts\python.exe app.py
```

Open http://127.0.0.1:5000 and sign in with your configured credentials. No default password, registration, password reset, or database is included. Environment variables must be set in the terminal that runs the app. `.env` files are not loaded automatically.

The password is hashed in memory. Signed, HttpOnly, SameSite cookies expire after two hours; forms have CSRF protection. A random session secret is generated each start. Set `SECRET_KEY` to a long random persistent secret if you need sessions to survive restarts. Do not commit secrets. This version binds to localhost and uses Flask's development server. Before public deployment, add login throttling, a production server, HTTPS, and set `COOKIE_SECURE=1`.

CLI remains available:

```powershell
.venv\Scripts\python.exe scanner.py
```

## What is included

- Responsive login page with password visibility toggle and sign out.
- Protected URL scanner dashboard calling `scanner.scan_url()`.
- HTTP/HTTPS validation; a missing scheme defaults to HTTPS; paths and queries preserve case.
- Explainable custom rules: HTTP +20; each keyword (`login`, `verify`, `update`, `secure`, `account`, `bank`) +10; known shortener +15; URL longer than 75 characters +10; numeric hostname +25. Capped at 100.
- Low 0–39, medium 40–69, high 70–100. These are heuristics and can produce false positives; HTTPS and low scores do not establish safety.
- VirusTotal submission and bounded polling, request timeouts, rate-limit and API error messages. API credentials stay on the server.
- Vendor counts shown separately from rule scores. Undetected means no opinion, not safe. Failed or pending vendor scans retain local scoring and show an explicit notice.
- No scan history is persisted. Submitted URLs are rendered as text rather than clickable links. The app does not fetch the target URL itself.

VirusTotal receives submitted URLs when an API key is set. Remove private links, tokens, and sensitive information before submission. The form asks for acknowledgement before scanning. Polling is synchronous and can occupy one request for roughly a minute, plus in-flight request timeouts. Free API quotas can be reached during polling.

## Checks

```powershell
.venv\Scripts\python.exe -m unittest discover -s tests -v
```

Tests mock VirusTotal; no real API calls or API keys are needed.

## Suggested next functions

1. Background scan jobs with quota-aware polling and retry, so requests remain responsive.
2. A documented, calibrated rule system with configurable weights and additional punycode/IP-address indicators.
3. Downloadable JSON/CSV reports without requiring a database.
4. Domain and IP reputation using dedicated VirusTotal endpoints.
5. Database-backed accounts and scan history when moving beyond the single-account v1.

API integration follows the [VirusTotal URL submission](https://docs.virustotal.com/reference/scan-url) and [analysis](https://docs.virustotal.com/reference/analysis) endpoints. Sessions use [Flask signed cookies](https://flask.palletsprojects.com/en/stable/quickstart/#sessions).

## Deploy the demo on Vercel (no database)

1. Push this project to your GitHub repository, then import `Kluuuz/ThreatLens` in Vercel.
2. Root Directory: repository root (`.`), where `app.py` and `vercel.json` live. Framework Preset: Flask. Leave build and output overrides unset.
3. Add environment variables for both Preview and Production before deploying:

   | Variable | Value |
   | --- | --- |
   | `SECRET_KEY` | A long random secret, identical across instances. Generate using `python -c "import secrets; print(secrets.token_hex(32))"`. |
   | `THREATLENS_USERNAME` | Your demo username; defaults to `analyst`. |
   | `THREATLENS_PASSWORD` | Your demo login password. |
   | `VT_API_KEY` | Optional VirusTotal API key. Omit for a local-rule-only demo. |

4. Deploy, then open the generated HTTPS URL and log in. After changing environment variables, redeploy.

`app.py` exports the Flask application for Vercel. `.python-version` selects Python 3.12. `vercel.json` allows up to 120 seconds per request; the scanner polls for up to 45 seconds after submission, with 15-second request timeouts. Pending, rate-limited, or failed VirusTotal scans show local scores with an explicit notice. No synthetic vendor verdicts are generated.

Login uses signed browser cookies and environment-configured credentials. No database, external session store, or file writes are needed. Vercel automatically enables Secure cookies. A persistent `SECRET_KEY` is required there so login works across serverless instances; the app fails at startup if it is absent. Local development can still use a generated session secret.

`.env.example` lists configuration names only; do not upload real credentials. `.vercelignore` excludes local environments, credentials, and tests from deployment. This repo is prepared for deployment; deploying still requires access to your Vercel account.

See [Vercel Flask deployment documentation](https://vercel.com/docs/frameworks/backend/flask).

Frontend assets live in `public/static/` for Vercel CDN serving, with Flask serving the same paths during local development.
