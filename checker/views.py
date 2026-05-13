import requests
from django.shortcuts import render

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
