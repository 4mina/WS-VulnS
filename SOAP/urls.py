from django.urls import path, re_path
from . import views

app_name = 'SOAP'

urlpatterns = [
    re_path(r'^(?P<ws_id>[0-9]+)/client/operation_request/(?P<soap_operation_id>\d+)/$',
            views.SoapClientOperationRequestView.as_view(), name='operation_request'),
    re_path(r'^(?P<ws_id>[0-9]+)/client/operation_response/(?P<soap_operation_response_id>\d+)/$',
            views.SoapClientOperationResponseView.as_view(), name='operation_response'),
    re_path(r'^(?P<ws_id>[0-9]+)/client/load_operations/$', views.SoapLoadOperationsView.as_view(),
            name='load_operations'),
    re_path(r'^(?P<ws_id>[0-9]+)/client/$', views.SoapClientView.as_view(), name='soap_client'),
    re_path(r'^(?P<ws_id>[0-9]+)/explorer/$', views.SoapExplorerView.as_view(), name='view_wsdl'),
    re_path(r'^(?P<ws_id>[0-9]+)/explorer/web_service_info/(?P<soap_web_service_id>\d+)/$',
            views.DisplaySoapWebServiceView.as_view(), name='web_service_info'),
    re_path(r'^(?P<ws_id>[0-9]+)/explorer/endpoint_info/(?P<soap_endpoint_id>\d+)/$',
            views.DisplayEndpointView.as_view(), name='endpoint_info'),
    re_path(r'^(?P<ws_id>[0-9]+)/explorer/operation_info/(?P<soap_operation_id>\d+)/$',
            views.DisplayOperationView.as_view(), name='operation_info'),
]
