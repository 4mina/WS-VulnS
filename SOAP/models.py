from django.db import models
from picklefield import fields

import json

from WebService.models import WebService, Request


class SoapWebService(WebService):
    address = models.URLField()

    class Meta:
        ordering = ('id',)


class Endpoint(models.Model):
    name = models.CharField(max_length=200)
    url = models.URLField()
    soap_version = models.CharField(max_length=3)
    web_service = models.ForeignKey(SoapWebService, on_delete=models.CASCADE, null=True)


class Operation(models.Model):
    name = models.CharField(max_length=200)
    endpoint = models.ForeignKey(Endpoint, on_delete=models.CASCADE, null=True)
    documentation = models.TextField(editable=False)
    parameters = fields.PickledObjectField()
    soap_action = models.CharField(max_length=1000, default='')

    def __str__(self):
        return json.dumps(self.parameters)


class SoapRequest(Request):
    operation = models.ForeignKey(Operation, on_delete=models.CASCADE, null=True)
