# SpoofShield

SpoofShield is a lightweight, self-hosted toolkit to inspect DNS and e-mail authentication indicators and keep investigation history. This repository uses PHP 8+, MySQL/MariaDB, and vanilla JavaScript/HTML for the frontend.

Important: this repo contains demo analysis heuristics, not conclusive cryptographic verification. Do NOT treat results as proof of compromise. See security notes below.

## Quick setup (Windows + XAMPP / VS Code)

1. Clone the repo:
   git clone https://github.com/<your>/SpoofShield-.git
   cd SpoofShield-

2. Create a config directory (if not present) and add environment variables:
   - Copy `.env.example` to a safe place and set variables.
   - For XAMPP, set environment variables in Apache/PHP or use a local `.env` loader (not included).

3. Database:
   - Create a database and user in MySQL/MariaDB.
   - Import schema:
     mysql -u root -p spoofshield < schema.sql

4. Ensure the PHP config allows dns_get_record and JSON and PDO extensions. PHP 8+ recommended.

5. Files / locations:
   - Put the repo webroot so `api/` and HTML pages are reachable by your server. Example:
     XAMPP: move repository folder to `C:\xampp\htdocs\spoofshield\`
     Then `http://localhost/spoofshield/` should show `index.html` or `scanner.html`.

6. Environment variables:
   - DB_HOST, DB_NAME, DB_USER, DB_PASS must be set for PHP to read via getenv(), or create `config/database.php` with local credentials (not recommended for production).

7. Start local PHP server (quick test):
   php -S 127.0.0.1:8000 -t .

8. Access UI:
   - DNS scanner: /scanner.html
   - Email analyser: /analyser.html
   - History: /history.html
   - Printable reports: /report.html?id=<investigation_id>

## Testing and verification (run these locally)

1. PHP syntax checks:
   php -l api/health.php
   php -l api/dns_scan.php
   php -l api/email_analyze.php
   php -l api/history.php
   php -l api/report.php
   (expect "No syntax errors detected" for each file)

2. API checks (example curl):
   curl -i -X GET http://127.0.0.1:8000/api/health.php

   Example DNS scan:
   curl -i -X POST http://127.0.0.1:8000/api/dns_scan.php -H "Content-Type: application/json" -d '{"domain":"example.com"}'

   Example email analyze:
   curl -i -X POST http://127.0.0.1:8000/api/email_analyze.php -H "Content-Type: application/json" -d '{"headers":"From: user@example.com\r\nReceived: from ..."}'

3. Database: confirm the scan_history table has rows:
   SELECT COUNT(*) FROM scan_history;

## Security & privacy notes
- All inputs are validated and limited size; servers should still be behind proper firewalls and HTTPS in production.
- Stored data must be treated as potentially sensitive (email headers). Consider pseudonymisation or not storing full header raw text.
- The app uses heuristics only. If Authentication-Results claims DKIM pass, that is a record claim — this app does not perform cryptographic verification of DKIM signature material.
- Do not expose this UI publicly without access controls and HTTPS.

## Troubleshooting
- If dns_get_record returns empty, check PHP's DNS functions are enabled and network/DNS access is permitted.
- If DB connection fails, check .env variables and that the DB user has permissions and the database exists.
