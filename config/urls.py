from django.contrib import admin
from django.urls import path
from checker.views import home, about, tools, blog, check_headers, check_ssl, check_subdomains, blog_http_headers, blog_google_cert

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', home, name='home'),
    path('about/', about, name='about'),
    path('tools/', tools, name='tools'),
    path('tools/headers/', check_headers, name='check_headers'),
    path('tools/ssl/', check_ssl, name='check_ssl'),
    path('tools/subdomains/', check_subdomains, name='check_subdomains'),
    path('blog/', blog, name='blog'),
    path('blog/http-security-headers/', blog_http_headers, name='blog_http_headers'),
    path('blog/google-cybersecurity-certificate/', blog_google_cert, name='blog_google_cert'),
]
