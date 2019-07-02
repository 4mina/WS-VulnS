from django.contrib import admin
from django.conf.urls import url
from django.urls import include


urlpatterns = [
    url(r'^admin/', admin.site.urls),
    url(r'^WS-VulnS/soap/', include('SOAP.urls')),
    url(r'^WS-VulnS/rest/', include('REST.urls')),
    url(r'^WS-VulnS/', include('WebService.urls')),
    url(r'^WS-VulnS/VulnTests/', include('Attacks.urls')),
]
