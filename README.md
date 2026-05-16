# eussec.com

Personal cybersecurity portfolio and security tools platform.

🌐 **Live:** [eussec.com](https://eussec.com)

## About

Built by [Emrah Ustundag](https://eussec.com/about/) — Software Engineering student at Atılım University with a focus on cybersecurity, backend development, and secure software practices.

## Tools

| Tool | Description | Status |
|------|-------------|--------|
| [HTTP Security Header Checker](https://eussec.com/tools/headers/) | Analyzes HTTP security headers and returns a security score | ✅ Live |
| [SSL/TLS Certificate Checker](https://eussec.com/tools/ssl/) | Checks SSL certificate validity, expiry, issuer, and cipher strength | ✅ Live |
| Subdomain Enumerator | Wordlist-based subdomain discovery | 🔜 Coming Soon |
| WHOIS & DNS Lookup | Domain reconnaissance tool | 🔜 Coming Soon |

## Tech Stack

- **Backend:** Python, Django
- **Frontend:** HTML, CSS, JavaScript
- **Deploy:** Railway
- **Domain:** Hostinger

## Run Locally

```bash
git clone https://github.com/emrahustundag/eussec.git
cd eussec
pip install -r requirements.txt
python manage.py migrate
python manage.py runserver
```
