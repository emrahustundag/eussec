import requests
import ssl
import socket
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from django.shortcuts import render

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


def check_headers(request):
    results = None
    error = None
    url = None
    score = None

    if request.method == 'POST':
        url = request.POST.get('url', '').strip()
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url

        try:
            response = requests.get(url, timeout=10, allow_redirects=True)
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
        except Exception as e:
            error = f'An error occurred: {str(e)}'

    return render(request, 'checker/header_checker.html', {
        'results': results,
        'error': error,
        'url': url,
        'score': score,
    })


def check_ssl(request):
    result = None
    error = None
    domain = None

    if request.method == 'POST':
        domain = request.POST.get('domain', '').strip()
        domain = domain.replace('https://', '').replace('http://', '').split('/')[0]

        try:
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


def check_subdomains(request):
    results = None
    error = None
    domain = None
    found_count = 0

    if request.method == 'POST':
        domain = request.POST.get('domain', '').strip()
        domain = domain.replace('https://', '').replace('http://', '').split('/')[0]

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

        except Exception as e:
            error = f'An error occurred: {str(e)}'

    return render(request, 'checker/subdomain_checker.html', {
        'results': results,
        'error': error,
        'domain': domain,
        'found_count': found_count,
    })
