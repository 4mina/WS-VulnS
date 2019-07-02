from django.contrib import admin
from REST.models import RestWebService, Path, Method, SwaggerResponse, RestRequest


class MethodAdmin(admin.ModelAdmin):
    empty_value_display = '-empty-'
    list_display = ('__str__', 'name', 'parameters', 'input_types', 'output_types')


admin.site.register(Method, MethodAdmin)


class RestWebServiceAdmin(admin.ModelAdmin):
    empty_value_display = "-empty-"
    list_display = ('__str__', 'paths')


admin.site.register(RestWebService, RestWebServiceAdmin)


class PathAdmin(admin.ModelAdmin):
    empty_value_display = '-empty-'
    list_display = ('__str__', 'get_methods')

    def get_methods(self, path):
        return ", ".join([l for l in path.methods])


admin.site.register(Path, PathAdmin)


class SwaggerResponseAdmin(admin.ModelAdmin):
    empty_value_display = '-empty-'
    list_display = ('__str__', 'schema')


admin.site.register(SwaggerResponse, SwaggerResponseAdmin)


class RestRequestAdmin(admin.ModelAdmin):
    empty_value_display = '-empty-'
    list_display = ('__str__', 'url', 'http_method', 'data', 'files', 'headers', 'category', 'attack_type')


admin.site.register(RestRequest, RestRequestAdmin)