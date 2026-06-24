import os
import re
import ipaddress
import requests
import ssl
import socket
import whois
import dns.resolver
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from django.shortcuts import render
from django.http import HttpResponseTooManyRequests
from django_ratelimit.decorators import ratelimit


def rate_limited(request):
    return HttpResponseTooManyRequests('Too many requests. Please wait a moment.')


def is_valid_domain(domain):
    """Sadece geçerli domain karakterlerine izin ver."""
    return bool(re.match(r'^[a-zA-Z0-9.-]+$', domain)) and len(domain) <= 253


def resolve_to_public_ip(hostname):
    """
    DNS rebinding koruması: IP'yi bir kez çöz, private/loopback/link-local ise None döndür.
    Dönen IP'yi sonraki bağlantılarda kullan — yeniden DNS çözümlemesi yapma.
    """
    try:
        ip_str = socket.gethostbyname(hostname)
        addr = ipaddress.ip_address(ip_str)
        if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved:
            return None
        return ip_str
    except Exception:
        return None


def is_private_host(hostname):
    return resolve_to_public_ip(hostname) is None

SUBDOMAIN_WORDLIST = [
    'www', 'mail', 'ftp', 'smtp', 'pop', 'imap', 'webmail', 'email',
    'admin', 'administrator', 'panel', 'dashboard', 'cpanel', 'whm',
    'api', 'app', 'apps', 'dev', 'development', 'staging', 'beta', 'test',
    'blog', 'news', 'forum', 'wiki', 'docs', 'help', 'support', 'status',
    'shop', 'store', 'portal', 'login', 'auth', 'secure', 'account',
    'cdn', 'static', 'assets', 'media', 'img', 'images', 'video',
    'ns1', 'ns2', 'ns3', 'mx', 'mx1', 'mx2',
    'remote', 'vpn', 'cloud', 'server', 'host', 'web', 'web1', 'web2',
    'git', 'gitlab', 'github', 'ci', 'jenkins', 'jira', 'monitor',
    'm', 'mobile', 'wap', 'api2', 'v1', 'v2', 'old', 'new', 'prod',
    'autodiscover', 'autoconfig', 'webdisk', 'calendar', 'chat',
]

HEADERS_INFO = {
    'Strict-Transport-Security': {
        'description': 'Forces HTTPS connections. Prevents protocol downgrade attacks.',
        'severity': 'high',
    },
    'Content-Security-Policy': {
        'description': 'Controls resources the browser can load. Prevents XSS attacks.',
        'severity': 'high',
    },
    'X-Frame-Options': {
        'description': 'Prevents clickjacking by controlling iframe embedding.',
        'severity': 'medium',
    },
    'X-Content-Type-Options': {
        'description': 'Prevents MIME-type sniffing. Should be set to "nosniff".',
        'severity': 'medium',
    },
    'Referrer-Policy': {
        'description': 'Controls how much referrer information is sent with requests.',
        'severity': 'low',
    },
    'Permissions-Policy': {
        'description': 'Controls browser features like camera, microphone, geolocation.',
        'severity': 'low',
    },
}


def home(request):
    return render(request, 'checker/home.html')


def about(request):
    return render(request, 'checker/about.html')


def tools(request):
    return render(request, 'checker/tools.html')


def blog(request):
    return render(request, 'checker/blog.html')


def blog_http_headers(request):
    return render(request, 'checker/blog_http_headers.html')


def blog_google_cert(request):
    return render(request, 'checker/blog_google_cert.html')


def blog_flipper_subghz(request):
    return render(request, 'checker/blog_flipper_subghz.html')


@ratelimit(key='ip', rate='10/m', method='POST', block=True)
def check_whois(request):
    result = None
    error = None
    domain = None

    if request.method == 'POST':
        domain = request.POST.get('domain', '').strip()
        domain = domain.replace('https://', '').replace('http://', '').split('/')[0]

        if not is_valid_domain(domain):
            error = 'Invalid domain name. Only letters, numbers, dots and hyphens are allowed.'
            return render(request, 'checker/whois_checker.html', {'result': None, 'error': error, 'domain': domain})

        if is_private_host(domain):
            error = 'Requests to internal/private network addresses are not allowed.'
            return render(request, 'checker/whois_checker.html', {'result': None, 'error': error, 'domain': domain})

        try:
            # WHOIS
            w = whois.whois(domain)

            # DNS
            dns_records = {}
            for record_type in ['A', 'MX', 'TXT', 'NS', 'CNAME']:
                try:
                    answers = dns.resolver.resolve(domain, record_type, lifetime=5)
                    dns_records[record_type] = [str(r) for r in answers]
                except Exception:
                    pass

            def fmt_date(d):
                if isinstance(d, list):
                    d = d[0]
                if hasattr(d, 'strftime'):
                    return d.strftime('%Y-%m-%d')
                return str(d)[:10] if d else None

            result = {
                'domain': domain,
                'registrar': w.registrar,
                'creation_date': fmt_date(w.creation_date),
                'expiration_date': fmt_date(w.expiration_date),
                'updated_date': fmt_date(w.updated_date),
                'name_servers': list(set([ns.lower() for ns in w.name_servers])) if w.name_servers else [],
                'status': w.status if isinstance(w.status, list) else [w.status] if w.status else [],
                'dns': dns_records,
            }

        except Exception:
            error = 'Could not retrieve information for this domain.'

    return render(request, 'checker/whois_checker.html', {
        'result': result,
        'error': error,
        'domain': domain,
    })


@ratelimit(key='ip', rate='10/m', method='POST', block=True)
def check_headers(request):
    results = None
    error = None
    url = None
    score = None

    if request.method == 'POST':
        url = request.POST.get('url', '').strip()
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url

        from urllib.parse import urlparse
        hostname = urlparse(url).hostname or ''
        if not is_valid_domain(hostname):
            error = 'Invalid URL. Only letters, numbers, dots and hyphens are allowed.'
            return render(request, 'checker/header_checker.html', {'results': None, 'error': error, 'url': url, 'score': None})

        try:
            from urllib.parse import urlparse
            hostname = urlparse(url).hostname or ''
            if is_private_host(hostname):
                error = 'Requests to internal/private network addresses are not allowed.'
                return render(request, 'checker/header_checker.html', {'results': None, 'error': error, 'url': url, 'score': None})

            response = requests.get(url, timeout=10, allow_redirects=False)
            # Redirect varsa hedef URL'yi de kontrol et
            if response.is_redirect or response.status_code in (301, 302, 303, 307, 308):
                location = response.headers.get('Location', '')
                from urllib.parse import urlparse as _up
                rhost = _up(location).hostname or ''
                if rhost and is_private_host(rhost):
                    error = 'Redirect target is an internal address.'
                    return render(request, 'checker/header_checker.html', {'results': None, 'error': error, 'url': url, 'score': None})
                response = requests.get(location or url, timeout=10, allow_redirects=False)
            headers = {k.lower(): v for k, v in response.headers.items()}

            results = []
            present = 0
            for header, info in HEADERS_INFO.items():
                found = header.lower() in headers
                if found:
                    present += 1
                results.append({
                    'header': header,
                    'present': found,
                    'value': headers.get(header.lower(), ''),
                    'description': info['description'],
                    'severity': info['severity'],
                })

            score = round((present / len(HEADERS_INFO)) * 100)

        except requests.exceptions.ConnectionError:
            error = 'Could not connect to the URL. Please check it and try again.'
        except requests.exceptions.Timeout:
            error = 'Request timed out.'
        except Exception:
            error = 'An error occurred while checking headers.'

    return render(request, 'checker/header_checker.html', {
        'results': results,
        'error': error,
        'url': url,
        'score': score,
    })


@ratelimit(key='ip', rate='10/m', method='POST', block=True)
def check_ssl(request):
    result = None
    error = None
    domain = None

    if request.method == 'POST':
        domain = request.POST.get('domain', '').strip()
        domain = domain.replace('https://', '').replace('http://', '').split('/')[0]

        if not is_valid_domain(domain):
            error = 'Invalid domain name. Only letters, numbers, dots and hyphens are allowed.'
            return render(request, 'checker/ssl_checker.html', {'result': None, 'error': error, 'domain': domain})

        try:
            if is_private_host(domain):
                error = 'Requests to internal/private network addresses are not allowed.'
                return render(request, 'checker/ssl_checker.html', {'result': None, 'error': error, 'domain': domain})

            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()

            not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
            not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
            days_left = (not_after - datetime.utcnow()).days

            issuer = dict(x[0] for x in cert['issuer'])
            subject = dict(x[0] for x in cert['subject'])

            result = {
                'domain': domain,
                'subject': subject.get('commonName', domain),
                'issuer': issuer.get('organizationName', 'Unknown'),
                'valid_from': not_before.strftime('%Y-%m-%d'),
                'valid_until': not_after.strftime('%Y-%m-%d'),
                'days_left': days_left,
                'cipher': cipher[0],
                'protocol': cipher[1],
                'valid': days_left > 0,
            }

        except ssl.SSLCertVerificationError:
            error = 'SSL certificate verification failed. The certificate may be invalid or self-signed.'
        except socket.timeout:
            error = 'Connection timed out.'
        except socket.gaierror:
            error = 'Domain not found. Please check the domain name.'
        except Exception as e:
            error = f'An error occurred: {str(e)}'

    return render(request, 'checker/ssl_checker.html', {
        'result': result,
        'error': error,
        'domain': domain,
    })


def resolve_subdomain(subdomain, domain):
    full = f'{subdomain}.{domain}'
    try:
        ip = socket.gethostbyname(full)
        return {'subdomain': full, 'ip': ip}
    except socket.gaierror:
        return None


def check_password(request):
    return render(request, 'checker/password_checker.html')


def hash_tool(request):
    return render(request, 'checker/hash_tool.html')


@ratelimit(key='ip', rate='10/m', method='POST', block=True)
def check_ip(request):
    result = None
    error = None
    ip = None

    if request.method == 'POST':
        ip = request.POST.get('ip', '').strip()

        if not re.match(r'^[0-9a-fA-F.:]+$', ip) or len(ip) > 45:
            error = 'Invalid IP address.'
            return render(request, 'checker/ip_checker.html', {'result': None, 'error': error, 'ip': ip})

        try:
            # ipinfo.io — konum ve ISP (API key gerekmez)
            ipinfo = requests.get(f'https://ipinfo.io/{ip}/json', timeout=8).json()

            # AbuseIPDB
            abuse_data = None
            api_key = os.environ.get('ABUSEIPDB_KEY', '')
            if api_key:
                abuse_resp = requests.get(
                    'https://api.abuseipdb.com/api/v2/check',
                    headers={'Key': api_key, 'Accept': 'application/json'},
                    params={'ipAddress': ip, 'maxAgeInDays': 90, 'verbose': True},
                    timeout=8
                )
                if abuse_resp.status_code == 200:
                    abuse_data = abuse_resp.json().get('data', {})

            if 'error' in ipinfo:
                error = f"Invalid IP address: {ip}"
            else:
                result = {
                    'ip': ip,
                    'hostname': ipinfo.get('hostname', '—'),
                    'city': ipinfo.get('city', '—'),
                    'region': ipinfo.get('region', '—'),
                    'country': ipinfo.get('country', '—'),
                    'org': ipinfo.get('org', '—'),
                    'timezone': ipinfo.get('timezone', '—'),
                    'abuse': abuse_data,
                }

        except Exception:
            error = 'Could not retrieve information for this IP.'

    return render(request, 'checker/ip_checker.html', {
        'result': result,
        'error': error,
        'ip': ip,
    })


COMMON_PORTS = {
    21: 'FTP',
    22: 'SSH',
    23: 'Telnet',
    25: 'SMTP',
    53: 'DNS',
    80: 'HTTP',
    110: 'POP3',
    143: 'IMAP',
    443: 'HTTPS',
    445: 'SMB',
    3306: 'MySQL',
    3389: 'RDP',
    5432: 'PostgreSQL',
    6379: 'Redis',
    8080: 'HTTP-Alt',
    8443: 'HTTPS-Alt',
    27017: 'MongoDB',
}


def scan_port(host, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except Exception:
        return False


@ratelimit(key='ip', rate='5/m', method='POST', block=True)
def check_ports(request):
    results = None
    error = None
    host = None
    open_count = 0

    if request.method == 'POST':
        host = request.POST.get('host', '').strip()
        host = host.replace('https://', '').replace('http://', '').split('/')[0]

        if not is_valid_domain(host):
            error = 'Invalid host. Only letters, numbers, dots and hyphens are allowed.'
            return render(request, 'checker/port_checker.html', {'results': None, 'error': error, 'host': host, 'open_count': 0})

        if is_private_host(host):
            error = 'Requests to internal/private network addresses are not allowed.'
            return render(request, 'checker/port_checker.html', {'results': None, 'error': error, 'host': host, 'open_count': 0})

        try:
            socket.gethostbyname(host)
        except socket.gaierror:
            error = 'Host not found. Please check the address.'
            return render(request, 'checker/port_checker.html', {'results': None, 'error': error, 'host': host, 'open_count': 0})

        try:
            found = []
            with ThreadPoolExecutor(max_workers=20) as executor:
                futures = {
                    executor.submit(scan_port, host, port): (port, service)
                    for port, service in COMMON_PORTS.items()
                }
                for future in as_completed(futures):
                    port, service = futures[future]
                    is_open = future.result()
                    found.append({'port': port, 'service': service, 'open': is_open})

            results = sorted(found, key=lambda x: x['port'])
            open_count = sum(1 for r in results if r['open'])

        except Exception:
            error = 'An error occurred while scanning ports.'

    return render(request, 'checker/port_checker.html', {
        'results': results,
        'error': error,
        'host': host,
        'open_count': open_count,
    })


@ratelimit(key='ip', rate='5/m', method='POST', block=True)
def check_subdomains(request):
    results = None
    error = None
    domain = None
    found_count = 0

    if request.method == 'POST':
        domain = request.POST.get('domain', '').strip()
        domain = domain.replace('https://', '').replace('http://', '').split('/')[0]

        if not is_valid_domain(domain):
            error = 'Invalid domain name. Only letters, numbers, dots and hyphens are allowed.'
            return render(request, 'checker/subdomain_checker.html', {
                'results': None, 'error': error, 'domain': domain, 'found_count': 0,
            })

        if is_private_host(domain):
            error = 'Requests to internal/private network addresses are not allowed.'
            return render(request, 'checker/subdomain_checker.html', {
                'results': None, 'error': error, 'domain': domain, 'found_count': 0,
            })

        try:
            socket.gethostbyname(domain)
        except socket.gaierror:
            error = 'Domain not found. Please check the domain name.'
            return render(request, 'checker/subdomain_checker.html', {
                'results': results, 'error': error, 'domain': domain, 'found_count': found_count,
            })

        try:
            found = []
            with ThreadPoolExecutor(max_workers=20) as executor:
                futures = {
                    executor.submit(resolve_subdomain, sub, domain): sub
                    for sub in SUBDOMAIN_WORDLIST
                }
                for future in as_completed(futures):
                    res = future.result()
                    if res:
                        found.append(res)

            results = sorted(found, key=lambda x: x['subdomain'])
            found_count = len(results)

        except Exception:
            error = 'An error occurred while scanning subdomains.'

    return render(request, 'checker/subdomain_checker.html', {
        'results': results,
        'error': error,
        'domain': domain,
        'found_count': found_count,
    })
