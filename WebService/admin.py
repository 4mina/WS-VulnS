from django.contrib import admin
from WebService.models import WebService, Response


admin.site.register(WebService)


class ResponseAdmin(admin.ModelAdmin):
    empty_value_display = '-empty-'
    list_display = ('__str__', 'content' ,'http_status_code' ,'time_to_first_byte')


admin.site.register(Response, ResponseAdmin)