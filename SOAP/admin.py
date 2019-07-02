from django.contrib import admin
from SOAP.models import SoapWebService, Operation, Endpoint, SoapRequest


class SoapWebServiceAdmin(admin.ModelAdmin):
    empty_value_display = "-empty-"
    list_display = ('__str__', 'name', 'type', 'documentation', 'address', 'description_url', 'description_file')


admin.site.register(SoapWebService, SoapWebServiceAdmin)


class EndpointAdmin(admin.ModelAdmin):
    empty_value_display = '-empty-'
    list_display = ('__str__', 'name', 'url', 'soap_version')


admin.site.register(Endpoint, EndpointAdmin)


class OperationAdmin(admin.ModelAdmin):
    empty_value_display = '-empty-'
    list_display = ('__str__', 'name', 'documentation', 'parameters')


admin.site.register(Operation, OperationAdmin)


class SoapRequestAdmin(admin.ModelAdmin):
    empty_value_display = '-empty-'
    list_display = ('__str__', 'url', 'http_method', 'operation', 'data', 'headers', 'files', 'category', 'attack_type')


admin.site.register(SoapRequest, SoapRequestAdmin)
