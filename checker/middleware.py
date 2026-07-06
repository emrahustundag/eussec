class SecurityHeadersMiddleware:
    """
    Sitenin kendi yanıtlarına güvenlik başlıkları ekler.
    CSP inline style/script'e izin verir çünkü şablonlar bunları kullanıyor,
    ama dış kaynaklı script/iframe yüklemesini engeller.
    """

    CSP = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "font-src 'self' data:; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self'"
    )

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        response.setdefault('Content-Security-Policy', self.CSP)
        response.setdefault('X-Frame-Options', 'DENY')
        response.setdefault('X-Content-Type-Options', 'nosniff')
        response.setdefault('Referrer-Policy', 'same-origin')
        response.setdefault('Permissions-Policy', 'geolocation=(), microphone=(), camera=()')
        return response
