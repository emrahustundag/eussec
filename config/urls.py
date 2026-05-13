from django.contrib import admin
from django.urls import path
from checker.views import home, about, tools, blog, check_headers

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', home, name='home'),
    path('about/', about, name='about'),
    path('tools/', tools, name='tools'),
    path('tools/headers/', check_headers, name='check_headers'),
    path('blog/', blog, name='blog'),
]
