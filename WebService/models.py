import html
import urllib3
from django.db import models
from WebService.choices import WS_TYPES, SOAP, TIMEOUT
from WebService.validators import validate_description_file, validate_description_url, validate_url_extension
from WebService.choices import HTTP_STATUS_CODES, REQUESTS_TYPES, HTTP_METHODS
import requests
from lxml.html import fromstring
from picklefield import fields
from Attacks.models import Attack


class WebService(models.Model):
    name = models.CharField(max_length=200)
    type = models.CharField(max_length=4, choices=WS_TYPES, default=SOAP, verbose_name="Web Service Type")
    description_file = models.FileField(blank=True,
                                        verbose_name="Description file", validators=[validate_description_file])
    description_url = models.URLField(blank=True, verbose_name="Description URL", validators=[validate_url_extension,
                                                                                              validate_description_url])
    documentation = models.TextField(editable=False)

    class Meta:
        ordering = ('id',)


class Request(models.Model):
    url = models.URLField(null=True)
    http_method = models.CharField(max_length=4, choices=HTTP_METHODS)
    data = fields.PickledObjectField(null=True, blank=True)
    files = fields.PickledObjectField(null=True)
    headers = fields.PickledObjectField(null=True)
    category = models.CharField(max_length=13, choices=REQUESTS_TYPES)
    # If category is not malicious there this field will be null
    attack_type = models.ForeignKey(Attack, on_delete=models.CASCADE, null=True)
    # If category is malicious and attack type is injection this field will contain the used pattern
    pattern = models.CharField(max_length=200, null=True)

    def __str__(self):
        return self.data

    def get_proxies(self):
        url = 'https://free-proxy-list.net/'
        response = requests.get(url)
        parser = fromstring(response.text)
        proxies = []
        for i in parser.xpath('//tbody/tr')[:10]:
            if i.xpath('.//td[7][contains(text(),"yes")]'):
                # Grabbing IP and corresponding PORT
                proxy = ":".join([i.xpath('.//td[1]/text()')[0], i.xpath('.//td[2]/text()')[0]])
                proxies.append(proxy)
        return proxies

    def send_request(self, files=None):
        timeout = TIMEOUT
        try:
            # s = requests.Session()
            # s.proxies = {"http": "http://61.233.25.166:80"}
            if self.http_method == 'POST':
                if files is not None:
                    resp = requests.post(self.url, files=files, headers=self.headers, timeout=timeout)
                else:
                    resp = requests.post(self.url, data=self.data, headers=self.headers, timeout=timeout)
            elif self.http_method == 'GET':
                resp = requests.get(self.url, params=self.data, headers=self.headers, timeout=timeout)
            elif self.http_method == 'PUT':
                resp = requests.put(self.url, data=self.data, headers=self.headers, timeout=timeout)
            elif self.http_method == 'DELETE':
                resp = requests.delete(self.url, data=self.data, headers=self.headers, timeout=timeout)
            elif self.http_method == 'PATCH':
                resp = requests.patch(self.url, data=self.data, headers=self.headers, timeout=timeout)
            elif self.http_method == 'HEAD':
                resp = requests.head(self.url, data=self.data, headers=self.headers, timeout=timeout)
            elif self.http_method == 'OPTIONS':
                resp = requests.options(self.url, data=self.data, headers=self.headers, timeout=timeout)
            response = Response()
            response.content = html.unescape(resp.text)
            response.http_status_code = resp.status_code
            response.time_to_first_byte = resp.elapsed.total_seconds()
        except requests.exceptions.ConnectionError:
            print('Connection Error !')
            response = Response()
            response.content = ''
            response.http_status_code = -1
            response.time_to_first_byte = -1
        except requests.exceptions.RequestException:
            print("Requests Exception has occured !")
            response = Response()
            response.content = ''
            response.http_status_code = -1
            response.time_to_first_byte = -1
        except urllib3.exceptions.HTTPError:
            print("Urllib3 New Connection Error !")
            response = Response()
            response.content = ''
            response.http_status_code = -1
            response.time_to_first_byte = -1
        return response


class Response(models.Model):
    request = models.ForeignKey(Request, on_delete=models.CASCADE, null=True)
    content = models.TextField(editable=False)
    http_status_code = models.CharField(max_length=3, choices=HTTP_STATUS_CODES)
    time_to_first_byte = models.FloatField()
