from django.db import models
from WebService.choices import HTTP_METHODS, HTTP_STATUS_CODES
from WebService.models import WebService
from WebService.models import Request
from picklefield import fields


class RestWebService(WebService):
    base_url = models.URLField(verbose_name='Base URL')
    paths = fields.PickledObjectField(null=True)

    class Meta:
        ordering = ('id',)


class Path(models.Model):
    web_service = models.ForeignKey(RestWebService, on_delete=models.CASCADE)
    name = models.CharField(max_length=100)
    methods = fields.PickledObjectField(null=True, choices=HTTP_METHODS)

    def get_base_url(self):
        web_service = RestWebService.objects.get(id=self.web_service_id)
        return web_service.base_url

    def get_methods_accept_xml(self):
        methods_accept_xml = []
        for method in self.method_set.all():
            if method.input_types:
                if 'application/xml' in method.input_types:
                    methods_accept_xml.append(method)
                    print(method.name)
        return methods_accept_xml


class Method(models.Model):
    path = models.ForeignKey(Path, on_delete=models.CASCADE)
    name = models.CharField(max_length=4, choices=HTTP_METHODS)
    summary = models.CharField(max_length=200, blank=True)
    description = models.CharField(max_length=200, blank=True)
    parameters = fields.PickledObjectField(null=True)
    input_types = fields.PickledObjectField(null=True)
    output_types = fields.PickledObjectField(null=True)

    def get_path_name(self):
        path = Path.objects.get(id=self.path_id)
        return path.name


class SwaggerResponse(models.Model):
    method = models.ForeignKey(Method, on_delete=models.CASCADE)
    http_code = models.CharField(max_length=3, choices=HTTP_STATUS_CODES)
    description = models.TextField(editable=False)
    schema = fields.PickledObjectField(null=True)


class RestRequest(Request):
    method = models.ForeignKey(Method, on_delete=models.CASCADE, null=True)