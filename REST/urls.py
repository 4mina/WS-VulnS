from django.conf.urls import url
from . import views

app_name = 'REST'


urlpatterns = [
    url(r'^(?P<pk>[0-9]+)/rest_client/$', views.RestClientView.as_view(), name='rest_client'),
    url(r'^(?P<pk>[0-9]+)/vuln_test/$', views.SwaggerExplorerView.as_view(), name='view_swagger'),
    url(r'^(?P<pk>[0-9]+)/vuln_test/rest_web_service/$', views.DisplayRestWebService.as_view(), name='rest_web_service_info'),
    url(r'^(?P<ws_id>[0-9]+)/vuln_test/path/(?P<pk>[0-9]+)/$', views.DisplayResource.as_view(), name='resource_info'),
    url(r'^(?P<ws_id>[0-9]+)/vuln_test/method/(?P<pk>[0-9]+)/$', views.DisplayMethod.as_view(), name='method_info'),
]

