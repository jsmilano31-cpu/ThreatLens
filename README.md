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
- Link Detective: URL anatomy with highlighted rule signals and plain-language explanations.
- Separate what-if simulation with rule toggles and Reset; the original score and vendor evidence remain visible.
- Three local-only fictional examples and browser-generated JSON reports.

## Present Link Detective

1. Sign in and choose **Stacked signals** under **Start with a case**. The example scores 100/100 from 105 raw points. Examples always run locally, even with an API key configured.
2. Inspect **URL anatomy** to see how protocol, hostname, port, path, and query relate to the triggered rules. An explicit port is shown only when supplied.
3. Under **What changes the score?**, uncheck HTTP. The simulated score becomes 85, while the original stays 100. Use **Reset all rules** to restore the simulation.
4. Select **Download JSON report** to save the original findings, timestamp, URL components, rule explanations, VirusTotal status/results, and a separate snapshot of the current simulation.

The other fictional cases score 0 (**Quiet link**) and 40 (**Look closer**). All use reserved `.example` domains. These are educational heuristic examples, not known malicious websites.

For your own URLs, choose **Local rules only** for immediate scoring without external requests. **Analyze with VirusTotal** uses the existing API integration and requires the consent checkbox. Without a key, it falls back to local rules with an explicit notice.

Simulation toggles exclude rules from a calculation; they do not edit the URL or rescan the website. A lower simulated score does not make the link safer. Keyword, length, and number rules can also flag legitimate URLs.

JSON downloads are created in your browser. Nothing is saved on the server or in a database. Reports contain the submitted URL, including its query, so remove sensitive information before analyzing or sharing a report. Simulation and download controls require JavaScript; ordinary analysis and examples work without it.

### Extending the core

`assess_url()` and `scan_url()` retain their existing score, level, URL, and reason fields. Assessments also include `analyzed_at` (UTC ISO timestamp) and `components`. Each rule reason has a stable `id`, `explanation`, and list of affected component names in addition to its original `label` and `points`.

Add a scoring signal through the helper inside `assess_url()` using a unique ID, points, explanation, and affected components. Anatomy, simulation, and report export consume that metadata automatically. `url_rep()` still returns only the numeric score.

VirusTotal receives submitted URLs when an API key is set. Remove private links, tokens, and sensitive information before submission. The form asks for acknowledgement before scanning. Polling is synchronous and can occupy one request for roughly a minute, plus in-flight request timeouts. Free API quotas can be reached during polling.

## Checks

```powershell
.venv\Scripts\python.exe -m unittest discover -s tests -v
node --test tests/test_simulation.cjs
```

Python tests mock VirusTotal; no real API calls or API keys are needed. Optional Node tests use the built-in test runner to check browser calculations and report contents against real Python assessments. Node is a development check only, not a runtime dependency.

## Suggested next functions

1. Background scan jobs with quota-aware polling and retry, so requests remain responsive.
2. A documented, calibrated rule system with configurable weights and additional punycode/IP-address indicators.
3. CSV report exports in addition to the included JSON download.
4. Domain and IP reputation using dedicated VirusTotal endpoints.
5. Database-backed accounts and scan history when moving beyond the single-account v1.

API integration follows the [VirusTotal URL submission](https://docs.virustotal.com/reference/scan-url) and [analysis](https://docs.virustotal.com/reference/analysis) endpoints. Sessions use [Flask signed cookies](https://flask.palletsprojects.com/en/stable/quickstart/#sessions).

## Deploy the demo on Vercel (no database)

1. Push this project to your GitHub repository, then import `jsmilano31-cpu/ThreatLens` in Vercel.
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

Login uses signed browser cookies and environment-configured credentials. No database, external session store, or file writes are needed. Vercel automatically enables Secure cookies. A persistent `SECRET_KEY` is required there so login works across serverless instances. If it or the login password is absent, the app starts and shows a setup page while keeping the analyst workspace closed. Local development can still use a generated session secret.

If Vercel shows `500 FUNCTION_INVOCATION_FAILED`, inspect its runtime logs. Earlier versions crashed during import when `SECRET_KEY` was missing. The setup page now identifies missing settings. Add the variables to Production and Preview, then redeploy; saved environment changes do not alter an existing deployment.

`.env.example` lists configuration names only; do not upload real credentials. `.vercelignore` excludes local environments, credentials, and tests from deployment. This repo is prepared for deployment; deploying still requires access to your Vercel account.

See [Vercel Flask deployment documentation](https://vercel.com/docs/frameworks/backend/flask).

Frontend assets live in `public/static/` for Vercel CDN serving, with Flask serving the same paths during local development.
