from django.shortcuts import render, get_object_or_404, redirect
from django.http import HttpResponse, HttpResponseRedirect, Http404
from django.views import generic
from django.db import transaction, IntegrityError

import os
import base64
import html
import json
import requests
import urllib3
import datetime
import string
import re
from time import sleep
from lxml import etree
from zeep import Client, Settings, xsd
from zeep.exceptions import XMLSyntaxError, WsdlSyntaxError
from random import randint, uniform, choice
from faker import Faker
from collections import Mapping

import SOAP.wsdl_types as wsdl_types
from WS_VulnS.settings import BASE_DIR
from WebService.choices import GOOD, BAD
from WebService.models import Response
from Attacks.models import XMLiAttack, XMLBombAttack, OversizedPayloadAttack, OversizedXMLAttack, SQLiAttack
from SOAP.models import SoapWebService, Endpoint, Operation, SoapRequest
from SOAP.forms import OperationForm


# This view gathers information on a SOAP Web Service and populates 3 models : SoapWebService, Endpoint and Operation
class WsdlSpecParser(generic.View):

    # This function parses the parameters of a given operation
    def parse_parameters(self, wsdl, elements, saved_enumerations, xml_tree):
        parameters = {}
        # Loop through the elements retrieved from Zeep
        for name, element in elements:
            parameters[name] = {}
            parameters[name]['optional'] = str(element.is_optional).capitalize()
            parameters[name]['max_occurrence'] = element.max_occurs
            # If the element type is complex
            if hasattr(element.type, 'elements'):
                complex_type = self.parse_parameters(wsdl, element.type.elements, saved_enumerations, xml_tree)
                parameters[name]['type'] = {'Complex': complex_type}
            # If the element type is simple
            else:
                data_type_temp = str(element.type).replace('(value)', '')
                # If the element's type is one of XSD types
                if data_type_temp.lower() in wsdl_types.DATA_TYPES_LIST:
                    if parameters[name]['max_occurrence'] != 'unbounded':
                        parameters[name]['type'] = data_type_temp
                    else:
                        parameters[name]['type'] = 'Array Of ' + data_type_temp
                # If the element's type is a custom type (Enumeration)
                else:
                    # set_enumerations.add(data_type_temp)
                    # If the enumeration already exists (To prevent searching the same one multiple times)
                    if data_type_temp in list(saved_enumerations.keys()):
                        parameters[name]['type'] = {'Enumeration': saved_enumerations.get(data_type_temp)}
                    # If the enumeration doesn't exist yet, parse the WSDL to retrieve its values
                    else:
                        enumeration_elements = xml_tree.xpath('//*[local-name()="simpleType"][@*[local-name('
                                                              ')="name"]="%s"]/*[local-name()="restriction"]/*['
                                                              'local-name()="enumeration"]/@value' % data_type_temp)
                        saved_enumerations.update({data_type_temp: enumeration_elements})
                        parameters[name]['type'] = {'Enumeration': enumeration_elements}

        return parameters

    # This function extracts the endpoints and operations of a given Web Service
    def parse_endpoints_operations(self, wsdl, web_service, list_services, xml_tree):
        endpoints = {}
        saved_enumerations = {}
        # Loop through all the services / endpoints
        for service in list_services.values():
            endpoints[service.name] = {}
            for port in service.ports.values():
                endpoint_type = str(type(port.binding))
                # Skip HTTP Bindings
                if 'http' not in endpoint_type.lower():
                    endpoints[service.name][port.name] = {}
                    endpoint = Endpoint()
                    endpoint.name = port.name
                    endpoint.url = list_services[service.name].ports[port.name].binding_options['address']
                    endpoint.web_service = web_service
                    binding_element = xml_tree.xpath('/*[local-name()="definitions"]/*[local-name()="binding"][@*['
                                                     'local-name()="name"]="%s"]/*[local-name()="binding"]' %
                                                     port.binding.name.localname)
                    for element in binding_element:
                        if 'schemas.xmlsoap.org/wsdl/soap/' in element.tag:
                            endpoint.soap_version = '1.1'
                        elif 'schemas.xmlsoap.org/wsdl/soap12/' in element.tag:
                            endpoint.soap_version = '1.2'
                    endpoint.save()
                    operations = []
                    # Loop through all the operations
                    for op in port.binding.all().values():
                        operation = Operation()
                        operation.name = op.name
                        operation.endpoint = endpoint
                        description = xml_tree.xpath('/*[local-name()="definitions"]/*[local-name()="portType"][@*['
                                                     'local-name()="name"]="%s"]/*[local-name()="operation"][@*['
                                                     'local-name()="name"]="%s"]/*[local-name('
                                                     ')="documentation"]/text()'
                                                     % (port.binding.port_type.name.localname, op.name))
                        if len(description) > 0:
                            operation.documentation = description[0]
                        soap_action = xml_tree.xpath('/*[local-name()="definitions"]/*[local-name()="binding"]'
                                                     '[@*[local-name()="name"]="%s"]/*[local-name()="operation"]'
                                                     '[@*[local-name()="name"]="%s"]/*[local-name()="operation"]'
                                                     '/@*[local-name()="soapAction"]'
                                                     % (port.binding.name.localname, op.name))
                        if len(soap_action) > 0:
                            operation.soap_action = soap_action[0]
                        parameters = {}
                        parameters['input'] = {}
                        input_elements = op.input.body.type.elements
                        parameters['input'] = self.parse_parameters(wsdl, input_elements, saved_enumerations, xml_tree)
                        parameters['output'] = {}
                        output_elements = op.output.body.type.elements
                        parameters['output'] = self.parse_parameters(wsdl, output_elements, saved_enumerations, xml_tree)
                        operation.parameters = parameters
                        operations.append(operation)
                    try:
                        with transaction.atomic():
                            for op in operations:
                                op.save()
                    except IntegrityError:
                        transaction.rollback()

    def parse_wsdl(self, web_service_id):
        try:
            web_service = SoapWebService.objects.get(id=web_service_id)
            # Get the URL and the WSDL
            if web_service.description_file.name is not '':
                try:
                    wsdl_url = web_service.description_file.path
                    wsdl = web_service.description_file.read()
                    web_service.description_file.close()
                except:
                    print('Get description file')
                    raise Http404
            else:
                wsdl_url = web_service.description_url
                try:
                    a = datetime.datetime.now()
                    response = requests.get(wsdl_url)
                    wsdl = response.content
                    b = datetime.datetime.now()
                except requests.exceptions.RequestException:
                    raise Http404
        except SoapWebService.DoesNotExist:
            print('Soap Web Service does not exist')
            raise Http404

        # Client object
        # transport = Transport(cache=SqliteCache())
        # history = HistoryPlugin()
        settings = Settings(raw_response=True)
        try:
            client = Client(wsdl_url, settings=settings)
        except (XMLSyntaxError, WsdlSyntaxError):
            print('Invalid XML file !')
        except requests.exceptions.RequestException:
            print("Request Exceptions")
        except urllib3.exceptions.HTTPError:
            print("Urllib3 Exceptions")
        else:
            list_services = client.wsdl.services
            service_name = list(list_services.keys())[0]
            # Default port
            default_port_name = list(list_services[service_name].ports.keys())[0]
            default_port_address = list_services[service_name].ports[default_port_name].binding_options['address']
            # Retrieve documentation
            xml_tree = etree.fromstring(wsdl)
            description = xml_tree.xpath('/*[local-name()="definitions"]/*[local-name()="documentation"]/text()')
            if len(description) > 0:
                SoapWebService.objects.filter(pk=web_service.pk).update(name=service_name,
                                                                        address=default_port_address,
                                                                        documentation=description[0])
            else:
                SoapWebService.objects.filter(pk=web_service.pk).update(name=service_name,
                                                                        address=default_port_address)

            a = datetime.datetime.now()
            self.parse_endpoints_operations(wsdl, web_service, list_services, xml_tree)
            b = datetime.datetime.now()

        return web_service


class SoapClientView(generic.ListView):
    template_name = 'SOAP/soap_client.html'
    pk_url_kwarg = 'ws_id'
    context_object_name = 'data'
    extra_context = {'ws_type': 'soap'}

    def get_queryset(self):
        try:
            web_service = SoapWebService.objects.get(id=self.kwargs.get('ws_id'))
            if not Endpoint.objects.filter(web_service_id=web_service.id):
                parser = WsdlSpecParser()
                web_service = parser.parse_wsdl(self.kwargs.get('ws_id'))
            return web_service
        except:
            raise Http404

    def get_context_data(self, *, object_list=None, **kwargs):
        data = super().get_context_data(**kwargs)
        web_service = SoapWebService.objects.get(id=self.kwargs.get('ws_id'))
        data['soapwebservice'] = web_service
        data['ws_id'] = self.kwargs.get('ws_id')
        return data


class SoapClientOperationRequestView(generic.FormView):
    template_name = 'SOAP/operation_request.html'
    form_class = OperationForm
    pk_url_kwarg = 'soap_operation_id'

    def get_context_data(self, **kwargs):
        data = super(SoapClientOperationRequestView, self).get_context_data(**kwargs)
        data['operation'] = Operation.objects.get(id=self.kwargs.get('soap_operation_id'))
        return data

    def get_form_kwargs(self):
        kwargs = super(SoapClientOperationRequestView, self).get_form_kwargs()
        kwargs.update({'soap_operation_id': self.kwargs.get('soap_operation_id')})
        return kwargs

    def post(self, request, *args, **kwargs):
        form = self.form_class(request.POST, soap_operation_id=self.kwargs.get('soap_operation_id'))
        if form.is_valid():
            operation, parameters = form.save()
            web_service = operation.endpoint.web_service
            non_malicious_requests_generator = SoapValidRequestsGeneration()
            wsdl_url = non_malicious_requests_generator.get_wsdl_url(web_service)
            client = non_malicious_requests_generator.get_client(wsdl_url)
            if client != '':
                list_services = client.wsdl.services
                service_name = list(list_services.keys())[0]
                service = client.bind(service_name, operation.endpoint.name)
                url = operation.endpoint.web_service.address

                headers = non_malicious_requests_generator.generate_operation_headers()
                http_body = non_malicious_requests_generator.generate_http_body(client, service, headers, operation.name,
                                                                                parameters)
                http_headers = non_malicious_requests_generator.generate_http_headers(operation.endpoint.soap_version,
                                                                                      operation.soap_action)

                operation_response = non_malicious_requests_generator.send_request(operation, url, http_headers, http_body)

                if operation_response != '':
                    return redirect('SOAP:operation_response', self.kwargs.get('ws_id'), operation_response.id)

                return HttpResponseRedirect(request.META.get('HTTP_REFERER'))

            return HttpResponseRedirect(request.META.get('HTTP_REFERER'))

        return HttpResponseRedirect(request.META.get('HTTP_REFERER'))


class SoapClientOperationResponseView(generic.DetailView):
    template_name = 'SOAP/operation_response.html'
    model = Response
    pk_url_kwarg = 'soap_operation_response_id'

    def get_context_data(self, **kwargs):
        context = super(SoapClientOperationResponseView, self).get_context_data(**kwargs)
        context['ws_type'] = 'soap'
        context['ws_id'] = self.kwargs.get("ws_id")
        return context


class SoapLoadOperationsView(generic.View):

    def get(self, request, ws_id):
        endpoint_id = request.GET['endpoint_id']
        operations = list(Operation.objects.filter(endpoint_id=endpoint_id).values('id', 'name'))
        return HttpResponse(json.dumps(operations), content_type='application/json')


class SoapRequestsGeneration(generic.View):
    pk_url_kwarg = 'ws_id'

    # Get WSDL URL from Web Service object
    def get_wsdl_url(self, web_service):
        if web_service.description_file.name is not '':
            try:
                wsdl_url = web_service.description_file.path
                web_service.description_file.close()
            except:
                raise Http404
        else:
            wsdl_url = web_service.description_url

        return wsdl_url

    # Get Zeep object "Client"
    def get_client(self, wsdl_url):
        settings = Settings(raw_response=True)
        try:
            client = Client(wsdl_url, settings=settings)
            return client
        except requests.exceptions.RequestException:
            print('Request Exceptions')
        except urllib3.exceptions.HTTPError:
            print('Urllib3 Exceptions')
        return ''

    # Generate HTTP Headers
    # Maybe add other meaningful headers later...
    def generate_http_headers(self, soap_version, soap_action):
        headers = {}

        # If xmlns:soap-env="http://www.w3.org/2003/05/soap-envelope" : SOAP 1.2
        if soap_version == '1.2':
            headers = {'Content-Type': 'application/soap+xml'}
        # If xmlns:soap-env="http://schemas.xmlsoap.org/soap/envelope" : SOAP 1.1
        elif soap_version == '1.1':
            headers = {'Content-Type': 'text/xml'}

        if soap_action != '' or soap_action != '""':
            headers.update({'SOAPAction': soap_action})

        return headers

    # Generate HTTP Body
    # Client as Client object in Zeep, headers as XML Element with value, operation as a string and parameters_values
    # as a dictionary
    # For skeletons, parameters_values should be empty or contain some special values
    def generate_http_body(self, client, service, headers, operation, parameters_values):
        # payload = client.create_message(service, operation, **parameters_values, _soapheaders=[headers])
        if headers:
            payload = client.create_message(service, operation, **parameters_values, _soapheaders=[headers])
        else:
            payload = client.create_message(service, operation, **parameters_values)
        payload_string = etree.tostring(payload).decode()

        return payload_string

    def send_request(self, operation, url, headers, data, attack=None, pattern=None):
        operation_request = SoapRequest(url=url, http_method='POST', headers=headers, data=data, operation=operation)

        # Non malicious request
        if attack is None:
            operation_request.category = GOOD
        # Malicious request
        else:
            operation_request.category = BAD
            operation_request.attack_type = attack
            if attack.family == 'Inj':
                operation_request.pattern = pattern

        operation_response = operation_request.send_request()

        try:
            with transaction.atomic():
                operation_request.save()
                operation_response.request = operation_request
                operation_response.save()
        except IntegrityError:
            transaction.rollback()

        return operation_response


class SoapValidRequestsGeneration(SoapRequestsGeneration):

    # Choose a random file given its type
    def choose_random_file(self, file_type):
        upload_dir = os.path.join(BASE_DIR, 'SOAP', 'files_to_upload')

        if file_type == 'text':
            upload_dir = os.path.join(upload_dir, 'texts')
        elif file_type == 'image':
            upload_dir = os.path.join(upload_dir, 'images')
        elif file_type == 'video':
            upload_dir = os.path.join(upload_dir, 'videos')

        file = os.path.join(upload_dir, choice(os.listdir(upload_dir)))
        return file

    # Generate a number given its type
    def generate_number(self, number_type):
        random_number = 0

        if number_type == 'decimal':
            random_number = randint(wsdl_types.MIN_LONG, wsdl_types.MAX_LONG)
        elif number_type == 'integer':
            random_number = randint(wsdl_types.MIN_LONG, wsdl_types.MAX_LONG)
        elif number_type == 'negativeinteger':
            random_number = randint(wsdl_types.MIN_LONG, -1)
        elif number_type == 'nonnegativeinteger':
            random_number = randint(0, wsdl_types.MAX_LONG)
        elif number_type == 'positiveinteger':
            random_number = randint(1, wsdl_types.MAX_LONG)
        elif number_type == 'nonpositiveinteger':
            random_number = randint(wsdl_types.MIN_LONG, 0)
        elif number_type == 'long':
            random_number = randint(wsdl_types.MIN_LONG, wsdl_types.MAX_LONG)
        elif number_type == 'unsignedlong':
            random_number = randint(0, wsdl_types.MAX_UNSIGNED_LONG)
        elif number_type == 'int':
            random_number = randint(wsdl_types.MIN_INT, wsdl_types.MAX_INT)
        elif number_type == 'unsignedint':
            random_number = randint(0, wsdl_types.MAX_UNSIGNED_INT)
        elif number_type == 'short':
            random_number = randint(wsdl_types.MIN_SHORT, wsdl_types.MAX_SHORT)
        elif number_type == 'unsignedshort':
            random_number = randint(0, wsdl_types.MAX_UNSIGNED_SHORT)
        elif number_type == 'byte':
            random_number = randint(wsdl_types.MIN_BYTE, wsdl_types.MAX_BYTE)
        elif number_type == 'unsignedbyte':
            random_number = randint(0, wsdl_types.MAX_UNSIGNED_BYTE)
        elif number_type == 'float':
            random_number = uniform(wsdl_types.MIN_FLOAT, wsdl_types.MAX_FLOAT)
        elif number_type == 'double':
            random_number = uniform(wsdl_types.MIN_FLOAT, wsdl_types.MAX_FLOAT)

        return random_number

    # Generate a string given its type
    def generate_string(self, string_type):
        random_string = ''

        if (string_type == 'string') or (string_type == 'normalizedstring') or (string_type == 'token'):
            random_string = choice(wsdl_types.STRING_VALUES)
        elif string_type == 'language':
            random_string = choice(wsdl_types.LANGUAGE_VALUES)
        elif (string_type == 'name') or (string_type == 'ncname') or (string_type == 'qname') or (
                string_type == 'notation'):
            random_string = choice(wsdl_types.NAME_VALUES)
        elif (string_type == 'id') or (string_type == 'idref'):
            random_string = choice(wsdl_types.ID_VALUES)
        elif string_type == 'entity':
            random_string = choice(wsdl_types.ENTITY_VALUES)
        elif string_type == 'nmtoken':
            random_string = choice(wsdl_types.NMTOKEN_VALUES)
        elif string_type == 'idrefs':
            random_string = choice(wsdl_types.IDREFS_VALUES)
        elif string_type == 'entities':
            random_string = choice(wsdl_types.ENTITIES_VALUES)
        elif string_type == 'nmtokens':
            random_string = choice(wsdl_types.NMTOKENS_VALUES)

        return random_string

    # Generate a date given its type
    def generate_date(self, date_type):
        random_date = ''
        fake = Faker()

        if date_type == 'duration':
            random_date = choice(wsdl_types.DURATION_VALUES)
        if date_type == 'daytimeduration':
            random_date = choice(wsdl_types.DAYTIMEDURATION_VALUES)
        if date_type == 'yearmonthduration':
            random_date = choice(wsdl_types.YEARMONTHDURATION_VALUES)
        elif date_type == 'datetime':
            random_date = fake.iso8601()
            random_date = datetime.datetime.strptime(random_date, '%Y-%m-%dT%H:%M:%S')
        elif date_type == 'datetimestamp':
            random_date = fake.iso8601() + 'Z'
        elif date_type == 'date':
            random_date = fake.date()
        elif date_type == 'time':
            random_date = fake.time()
        elif date_type == 'gyear':
            random_date = fake.year()
        elif date_type == 'gmonth':
            random_date = '--' + fake.month()
        elif date_type == 'gday':
            random_date = '---' + fake.day_of_month()
        elif date_type == 'gyearmonth':
            random_date = fake.year() + '-' + fake.month()
        elif date_type == 'gmonthday':
            random_date = '--' + fake.month() + '-' + fake.day_of_month()

        return random_date

    # Generate other types needed for XSD
    def generate_misc(self, misc_type):
        random_misc = ''
        fake = Faker()

        if misc_type == 'boolean':
            random_misc = choice(wsdl_types.BOOLEAN_VALUES)
        elif misc_type == 'anyuri':
            random_misc = fake.uri()
        elif misc_type == 'hexbinary':
            random_misc = choice(wsdl_types.HEXBINARY_VALUES)
        elif misc_type == 'base64binary':
            random_file = self.choose_random_file(choice(wsdl_types.FILE_VALUES))
            with open(random_file, 'rb') as file:
                encoded_file = base64.b64encode(file.read())
            random_misc = encoded_file.decode('ascii')

        return random_misc

    # Generate valid request parameters for a given operation that are needed to generate HTTP Body
    def generate_operation_parameters(self, parameters):
        parameters_values = {}

        for key, value in parameters.items():
            if isinstance(value['type'], Mapping):
                # If 'Enumeration'
                if 'Enumeration' in value['type']:
                    parameters_values[key] = choice(value['type']['Enumeration'])
                # If 'Complex'
                else:
                    parameters_values[key] = self.generate_operation_parameters(value['type']['Complex'])
            else:
                if value['type'].lower() in wsdl_types.NUMBER_TYPES_LIST:
                    parameters_values[key] = self.generate_number(value['type'].lower())
                elif value['type'].lower() in wsdl_types.STRING_TYPES_LIST:
                    parameters_values[key] = self.generate_string(value['type'].lower())
                elif value['type'].lower() in wsdl_types.DATE_TYPES_LIST:
                    parameters_values[key] = self.generate_date(value['type'].lower())
                elif value['type'].lower() in wsdl_types.MISC_TYPES_LIST:
                    parameters_values[key] = self.generate_misc(value['type'].lower())

        return parameters_values

    # Generate SOAP Headers for a given operation
    # For now we don't need SOAP Headers, maybe later...
    def generate_operation_headers(self):
        return {}

    def send_valid_request(self, operation, number_requests, simulate=False):
        responses = []

        web_service = operation.endpoint.web_service
        wsdl_url = self.get_wsdl_url(web_service)
        client = self.get_client(wsdl_url)
        if client != '':
            list_services = client.wsdl.services
            service_name = list(list_services.keys())[0]
            service = client.bind(service_name, operation.endpoint.name)
            url = operation.endpoint.web_service.address

            for i in range(number_requests):
                parameters = self.generate_operation_parameters(operation.parameters['input'])
                headers = self.generate_operation_headers()
                http_body = self.generate_http_body(client, service, headers, operation.name, parameters)
                http_headers = self.generate_http_headers(operation.endpoint.soap_version, operation.soap_action)
                # responses.append({'url': url, 'headers': headers, 'body': http_body})
                responses.append(self.send_request(operation, url, http_headers, http_body))
                if simulate:
                    sleep(5)

        return responses

    def send_fuzzed_request(self, operation, number_requests):
        responses = []

        web_service = operation.endpoint.web_service
        wsdl_url = self.get_wsdl_url(web_service)
        client = self.get_client(wsdl_url)
        if client != '':
            list_services = client.wsdl.services
            service_name = list(list_services.keys())[0]
            service = client.bind(service_name, operation.endpoint.name)
            url = operation.endpoint.web_service.address

            for i in range(number_requests):
                parameters = self.generate_operation_parameters(operation.parameters['input'])
                headers = self.generate_operation_headers()
                http_body = self.generate_http_body(client, service, headers, operation.name, parameters)
                http_headers = self.generate_http_headers(operation.endpoint.soap_version, operation.soap_action)

                parameter_value = ''
                fuzzed_choice = randint(0, 2)
                if fuzzed_choice == 0:
                    characters = string.ascii_letters
                    parameter_value = ''.join(choice(characters) for i in range(randint(0, 500)))
                elif fuzzed_choice == 1:
                    parameter_value = str(randint(0, 10 ** 20))
                elif fuzzed_choice == 2:
                    parameter_value = str(uniform(0, 10 ** 20))

                if operation.parameters['input']:
                    number_parameters = len(list(operation.parameters['input'].keys()))
                    parameters = list(operation.parameters['input'].keys())
                    random_parameter_name = parameters[randint(0, number_parameters - 1)]
                    body_tree = etree.fromstring(http_body)
                    parameter_element = body_tree.xpath('/*[local-name()="Envelope"]/*[local-name()="Body"]/*['
                                                        'local-name()="%s"]/*[local-name()="%s"]' %
                                                        (operation.name, random_parameter_name))
                    if len(parameter_element) > 0:
                        parameter_element[0].text = parameter_value

                else:
                    body_tree = etree.fromstring(http_body)
                    operation_element = body_tree.xpath('/*[local-name()="Envelope"]/*[local-name()="Body"]/*['
                                                        'local-name()="%s"]' % operation.name)
                    if len(operation_element) > 0:
                        injection_element = etree.SubElement(operation_element[0], 'Fuzzed_Parameter')
                        injection_element.text = parameter_value

                http_body = html.unescape(etree.tostring(body_tree).decode())
                responses.append(self.send_request(operation, url, http_headers, http_body))

        return responses


# This class needs to inherit the class 'SoapValidRequestsGeneration' because even for malicious requests we need to
# generate valid parameters values
class SoapMaliciousRequestsGeneration(SoapValidRequestsGeneration):

    # Generate fake SOAP Headers for a given operation
    def generate_fake_operation_headers(self):
        headers_element = xsd.ComplexType([xsd.Element('item', xsd.String())])
        headers_value = headers_element(item='?')

        return headers_value

    # Generate an initial request with valid parameters that will be used to generate attacks
    def generate_initial_operation_request(self, operation):
        web_service = operation.endpoint.web_service
        wsdl_url = self.get_wsdl_url(web_service)
        client = self.get_client(wsdl_url)
        if client != '':
            list_services = client.wsdl.services
            service_name = list(list_services.keys())[0]
            service = client.bind(service_name, operation.endpoint.name)

            headers = self.generate_fake_operation_headers()
            parameters = self.generate_operation_parameters(operation.parameters['input'])
            http_headers = self.generate_http_headers(operation.endpoint.soap_version, operation.soap_action)
            http_body = self.generate_http_body(client, service, headers, operation.name, parameters)

            return http_headers, http_body

        return {}, ''

    def generate_oversized_xml_request(self, oversized_xml_type, payload, operation, http_body_tree,
                                       parameter_name=None):
        http_body_string = ''

        # Because the lxml library can't handle large files and strings, we first use it to parse the request skeleton
        # and add the necessary tags / attributes, and then we replace them / their content with regex

        if oversized_xml_type == 'LongNames':
            # Add an oversized tag with an extra long name as parameter
            operation_element = http_body_tree.xpath('/*[local-name()="Envelope"]/*[local-name()="Body"]/*['
                                                     'local-name()="%s"]' % operation.name)
            if len(operation_element) > 0:
                oversized_element = etree.SubElement(operation_element[0], 'Temporary_Name')
                oversized_element.text = ''
            temporary = etree.tostring(http_body_tree).decode()
            http_body_string = re.sub('<Temporary_Name></Temporary_Name>', '<{oversized_payload}></{oversized_payload}>'
                                      .format(oversized_payload=payload), temporary)

        elif oversized_xml_type == 'OverAttrContent':
            # If the operation has inputs, insert the oversized payload inside the one of the inputs' attribute
            if parameter_name is not None:
                parameter_element = http_body_tree.xpath('/*[local-name()="Envelope"]/*[local-name()="Body"]/*['
                                                         'local-name()="%s"]/*[local-name()="%s"]' %
                                                         (operation.name, parameter_name))
                if len(parameter_element) > 0:
                    parameter_element[0].attrib['oversized_attribute'] = ''
                temporary = etree.tostring(http_body_tree).decode()
                http_body_string = re.sub('oversized_attribute=""', 'oversized_attribute="{oversized_payload}"'.format(
                                          oversized_payload=payload), temporary)
            # Else, create a new <Oversized> tag and add an attribute with the oversized payload
            else:
                operation_element = http_body_tree.xpath('/*[local-name()="Envelope"]/*[local-name()="Body"]/*['
                                                         'local-name()="%s"]' % operation.name)
                if len(operation_element) > 0:
                    oversized_element = etree.SubElement(operation_element[0], 'Oversized')
                    oversized_element.text = ''
                    oversized_element.attrib['oversized_attribute'] = ''
                temporary = etree.tostring(http_body_tree).decode()
                http_body_string = re.sub('<Oversized oversized_attribute="">', '<Oversized oversized_attribute="'
                                          '{oversized_payload}">'.format(oversized_payload=payload),
                                          temporary)

        return http_body_string

    def generate_oversized_payload_request(self, oversized_payload_type, payload, operation, http_body_tree,
                                           parameter_name=None):
        http_body_string = ''

        # Because the lxml library can't handle large files and strings, we first use it to parse the request skeleton
        # and add the necessary tags / attributes, and then we replace them / their content with regex

        if oversized_payload_type == 'Envelope':
            # Add the <Oversized> tag with the oversized payload after the SOAP Header and inside the SOAP Envelope
            soap_body = http_body_tree.xpath('/*[local-name()="Envelope"]/*[local-name()="Body"]')
            if operation.endpoint.soap_version == '1.1':
                oversized_element = etree.Element('{http://schemas.xmlsoap.org/soap/envelope/}Oversized')
            elif operation.endpoint.soap_version == '1.2':
                oversized_element = etree.Element('{http://www.w3.org/2003/05/soap-envelope}Oversized')
            oversized_element.text = ''
            if len(soap_body) > 0:
                soap_body[0].addnext(oversized_element)
            temporary = etree.tostring(http_body_tree).decode()
            http_body_string = re.sub('<{prefix}:Oversized></{prefix}:Oversized>'.format(
                                      prefix=oversized_element.prefix), '<{prefix}:Oversized>{oversized_payload}'
                                      '</{prefix}:Oversized>'.format(prefix=oversized_element.prefix,
                                                                     oversized_payload=payload), temporary)

        elif oversized_payload_type == 'Header':
            # Remove the <item> tag in the SOAP Header and replace it with the <Oversized> tag
            item_element = http_body_tree.xpath('/*[local-name()="Envelope"]/*[local-name()="Header"]/item')
            if len(item_element) > 0:
                item_element[0].getparent().remove(item_element[0])
            soap_headers = http_body_tree.xpath('/*[local-name()="Envelope"]/*[local-name()="Header"]')
            if len(soap_headers) > 0:
                oversized_element = etree.SubElement(soap_headers[0], 'Oversized')
                oversized_element.text = ''
            temporary = etree.tostring(http_body_tree).decode()
            http_body_string = re.sub('<Oversized></Oversized>', '<Oversized>{oversized_payload}</Oversized>'.format(
                                      oversized_payload=payload), temporary)

        elif oversized_payload_type == 'Body':
            # If the operation has inputs, insert the oversized payload inside one of the inputs
            if parameter_name is not None:
                parameter_element = http_body_tree.xpath('/*[local-name()="Envelope"]/*[local-name()="Body"]/*['
                                                         'local-name()="%s"]/*[local-name()="%s"]' %
                                                         (operation.name, parameter_name))
                if len(parameter_element) > 0:
                    parameter_element[0].text = ''
                    temporary = etree.tostring(http_body_tree).decode()
                    if parameter_element[0].prefix is not None:
                        http_body_string = re.sub('<{prefix}:{parameter_name}></{prefix}:{parameter_name}>'.
                                                  format(prefix=parameter_element[0].prefix,
                                                         parameter_name=parameter_name),
                                                  '<{prefix}:{parameter_name}>{oversized_payload}</{prefix}:'
                                                  '{parameter_name}>'.
                                                  format(prefix=parameter_element[0].prefix,
                                                         parameter_name=parameter_name,
                                                         oversized_payload=payload), temporary)
                    else:
                        http_body_string = re.sub('<{parameter_name}></{parameter_name}>'.format(
                                                  parameter_name=parameter_name), '<{parameter_name}>'
                                                  '{oversized_payload}</{parameter_name}>'.format(
                                                  parameter_name=parameter_name,
                                                  oversized_payload=payload), temporary)
            # Else, create a new <Oversized> tag and insert it inside the operation element
            else:
                operation_element = http_body_tree.xpath('/*[local-name()="Envelope"]/*[local-name()="Body"]/*['
                                                         'local-name()="%s"]' % operation.name)
                if len(operation_element) > 0:
                    oversized_element = etree.SubElement(operation_element[0], 'Oversized')
                    oversized_element.text = ''
                temporary = etree.tostring(http_body_tree).decode()
                http_body_string = re.sub('<Oversized></Oversized>', '<Oversized>{oversized_payload}</Oversized>'.format
                                          (oversized_payload=payload), temporary)

        return http_body_string

    def generate_xml_injection_request(self, xml_injection_type, pattern, operation, http_body_tree,
                                       parameter_name=None, parameter_index=None, number_parameters=None):

        if xml_injection_type == 'Malformed' or xml_injection_type == 'XPath':
            if parameter_name is not None:
                parameter_element = http_body_tree.xpath('/*[local-name()="Envelope"]/*[local-name()="Body"]/*['
                                                         'local-name()="%s"]/*[local-name()="%s"]' %
                                                         (operation.name, parameter_name))
                if len(parameter_element) > 0:
                    parameter_element[0].text = pattern
            else:
                operation_element = http_body_tree.xpath('/*[local-name()="Envelope"]/*[local-name()="Body"]/*['
                                                         'local-name()="%s"]' % operation.name)
                if len(operation_element) > 0:
                    injection_element = etree.SubElement(operation_element[0], 'Injection')
                    injection_element.text = pattern

        elif xml_injection_type == 'Replicating':
            if parameter_name is not None:
                parameter_element = http_body_tree.xpath('/*[local-name()="Envelope"]/*[local-name()="Body"]/*['
                                                         'local-name()="%s"]/*[local-name()="%s"]' %
                                                         (operation.name, parameter_name))
                if len(parameter_element) > 0:
                    duplicated_parameter_element = etree.Element(parameter_element[0].tag)
                    duplicated_parameter_element.text = pattern
                    if parameter_index == 0 or parameter_index == number_parameters - 1:
                        parameter_element[0].addnext(duplicated_parameter_element)
                    else:
                        next_parameter_element = parameter_element[0].getnext()
                        next_parameter_element.addnext(duplicated_parameter_element)
                        duplicated_next_parameter_element = etree.Element(next_parameter_element.tag)
                        duplicated_next_parameter_element.text = next_parameter_element.text
                        duplicated_parameter_element.addnext(duplicated_next_parameter_element)
            else:
                operation_element = http_body_tree.xpath('/*[local-name()="Envelope"]/*[local-name()="Body"]/*['
                                                         'local-name()="%s"]' % operation.name)
                if len(operation_element) > 0:
                    injection_element = etree.SubElement(operation_element[0], 'Injection')
                    injection_element.text = pattern

        http_body_string = html.unescape(etree.tostring(http_body_tree).decode())

        return http_body_string

    def generate_sql_injection_request(self, pattern, operation, http_body_tree, parameter_name=None):

        if parameter_name is not None:
            parameter_element = http_body_tree.xpath('/*[local-name()="Envelope"]/*[local-name()="Body"]/*['
                                                     'local-name()="%s"]/*[local-name()="%s"]' %
                                                     (operation.name, parameter_name))
            if len(parameter_element) > 0:
                parameter_element[0].text = pattern

        else:
            operation_element = http_body_tree.xpath('/*[local-name()="Envelope"]/*[local-name()="Body"]/*['
                                                     'local-name()="%s"]' % operation.name)
            if len(operation_element) > 0:
                oversized_element = etree.SubElement(operation_element[0], 'Injection')
                oversized_element.text = pattern

        http_body_string = html.unescape(etree.tostring(http_body_tree).decode())

        return http_body_string

    def generate_xml_bomb_request(self, xml_bomb_type, payload, operation, http_body_tree):
        http_body_string = ''

        operation_element = http_body_tree.xpath('/*[local-name()="Envelope"]/*[local-name()="Body"]/*['
                                                 'local-name()="%s"]' % operation.name)
        if len(operation_element) > 0:
            oversized_element = etree.SubElement(operation_element[0], 'Bomb')
            oversized_element.text = ''
        temporary = etree.tostring(http_body_tree).decode()

        if xml_bomb_type == 'BIL' or xml_bomb_type == 'ExtEnt':
            reference = re.findall(r'<lolz>.*?</lolz>', payload)
            dtd = payload
            if len(reference) > 0:
                dtd = dtd.replace(reference[0], '')
                http_body_string = re.sub('<Bomb></Bomb>', reference[0], temporary)
                http_body_string = dtd + http_body_string

        elif xml_bomb_type == 'IntEnt':
            reference = re.findall(r'<kaboom>.*?</kaboom>', payload)
            dtd = payload
            if len(reference) > 0:
                dtd = dtd.replace(reference[0], '')
                http_body_string = re.sub('<Bomb></Bomb>', reference[0], temporary)
                http_body_string = dtd + http_body_string

        return http_body_string

    def send_malicious_request(self, selected_attacks, operation):
        url = operation.endpoint.web_service.address
        headers, body_string = self.generate_initial_operation_request(operation)
        responses = {}

        if body_string != '':
            if 'overxml' in selected_attacks:
                responses.update({'overxml': []})
                # Get latest Oversized XML object
                latest_oversized_xml = OversizedXMLAttack.objects.all().order_by('-id')[:1]

                # Generate the HTTP body of the malicious request for each operation input (If they exist)
                if operation.parameters['input']:
                    number_parameters = len(list(operation.parameters['input'].keys()))
                    parameters = list(operation.parameters['input'].keys())
                    for i in range(0, number_parameters):
                        body_tree = etree.fromstring(body_string)
                        body = self.generate_oversized_xml_request(latest_oversized_xml[0].type,
                                                                   latest_oversized_xml[0].payload,
                                                                   operation, body_tree, parameters[i])
                        responses['overxml'].append(self.send_request(operation, url, headers, body,
                                                                      latest_oversized_xml[0]))

                else:
                    body_tree = etree.fromstring(body_string)
                    body = self.generate_oversized_xml_request(latest_oversized_xml[0].type,
                                                               latest_oversized_xml[0].payload,
                                                               operation, body_tree)
                    responses['overxml'].append(self.send_request(operation, url, headers, body, latest_oversized_xml[0]))

            if 'overpayload' in selected_attacks:
                responses.update({'overpayload': []})
                # Get latest Oversized Payload object
                latest_oversized_payload = OversizedPayloadAttack.objects.all().order_by('-id')[:1]

                # Generate the HTTP body of the malicious request for each operation input (If they exist)
                if operation.parameters['input']:
                    number_parameters = len(list(operation.parameters['input'].keys()))
                    parameters = list(operation.parameters['input'].keys())
                    for i in range(0, number_parameters):
                        body_tree = etree.fromstring(body_string)
                        body = self.generate_oversized_payload_request(latest_oversized_payload[0].type,
                                                                       latest_oversized_payload[0].payload, operation,
                                                                       body_tree, parameters[i])
                        responses['overpayload'].append(self.send_request(operation, url, headers, body,
                                                                          latest_oversized_payload[0]))

                else:
                    body_tree = etree.fromstring(body_string)
                    body = self.generate_oversized_payload_request(latest_oversized_payload[0].type,
                                                                   latest_oversized_payload[0].payload, operation,
                                                                   body_tree)
                    responses['overpayload'].append(self.send_request(operation, url, headers, body,
                                                                      latest_oversized_payload[0]))

            if 'xmli' in selected_attacks:
                responses.update({'xmli': []})
                # Get latest XML Injection object
                latest_xml_injection = XMLiAttack.objects.all().order_by('-id')[:3]

                # Generate the HTTP body of the malicious request for each operation input (If they exist) and for each
                # pattern
                if operation.parameters['input']:
                    number_parameters = len(list(operation.parameters['input'].keys()))
                    parameters = list(operation.parameters['input'].keys())
                    for i in range(0, number_parameters):
                        for xml_injection in latest_xml_injection:
                            for pattern in xml_injection.patterns:
                                body_tree = etree.fromstring(body_string)
                                body = self.generate_xml_injection_request(xml_injection.type, pattern, operation,
                                                                           body_tree, parameters[i], i, number_parameters)
                                responses['xmli'].append(self.send_request(operation, url, headers, body, xml_injection,
                                                                           pattern))

                else:
                    for xml_injection in latest_xml_injection:
                        for pattern in xml_injection.patterns:
                            body_tree = etree.fromstring(body_string)
                            body = self.generate_xml_injection_request(xml_injection.type, pattern, operation,
                                                                       body_tree)
                            responses['xmli'].append(self.send_request(operation, url, headers, body, xml_injection,
                                                                       pattern))

            if 'sqli' in selected_attacks:
                responses.update({'sqli': []})
                # Get latest 3 SQL Injection objects
                latest_sql_injection = SQLiAttack.objects.all().order_by('-id')[:4]

                # Generate the HTTP body of the malicious request for each operation input (If they exist) and for each
                # pattern
                if operation.parameters['input']:
                    number_parameters = len(list(operation.parameters['input'].keys()))
                    parameters = list(operation.parameters['input'].keys())
                    for i in range(0, number_parameters):
                        for sql_injection in latest_sql_injection:
                            for pattern in sql_injection.patterns:
                                body_tree = etree.fromstring(body_string)
                                body = self.generate_sql_injection_request(pattern, operation, body_tree, parameters[i])
                                responses['sqli'].append(self.send_request(operation, url, headers, body, sql_injection,
                                                                           pattern))

                else:
                    for sql_injection in latest_sql_injection:
                        for pattern in sql_injection.patterns:
                            body_tree = etree.fromstring(body_string)
                            body = self.generate_sql_injection_request(pattern, operation, body_tree)
                            responses['sqli'].append(self.send_request(operation, url, headers, body, sql_injection,
                                                                       pattern))

            if 'xmlb' in selected_attacks:
                responses.update({'xmlb': []})
                # Get latest 3 XML Bomb objects
                latest_xml_bomb = XMLBombAttack.objects.all().order_by('-id')[:3]

                # Generate the HTTP body of the malicious request for each object
                if operation.parameters['input']:
                    number_parameters = len(list(operation.parameters['input'].keys()))
                    for i in range(0, number_parameters):
                        for xml_bomb in latest_xml_bomb:
                            body_tree = etree.fromstring(body_string)
                            body = self.generate_xml_bomb_request(xml_bomb.type, xml_bomb.payload, operation, body_tree)
                            responses['xmlb'].append(self.send_request(operation, url, headers, body, xml_bomb))
                            # responses['xmlb'].append({'url': url, 'headers': headers, 'body': body})
                else:
                    for xml_bomb in latest_xml_bomb:
                        body_tree = etree.fromstring(body_string)
                        body = self.generate_xml_bomb_request(xml_bomb.type, xml_bomb.payload, operation, body_tree)
                        responses['xmlb'].append(self.send_request(operation, url, headers, body, xml_bomb))

        else:
            if 'overxml' in selected_attacks:
                responses.update({'overxml': []})
            if 'overpayload' in selected_attacks:
                responses.update({'overpayload': []})
            if 'xmli' in selected_attacks:
                responses.update({'xmli': []})
            if 'sqli' in selected_attacks:
                responses.update({'sqli': []})
            if 'xmlb' in selected_attacks:
                responses.update({'xmlb': []})

        return responses


# This view creates a Tree View from the Web Service' endpoints and operations
class SoapExplorerView(generic.ListView):
    template_name = 'SOAP/soap_explorer.html'
    context_object_name = 'data'
    extra_context = {'ws_type': 'soap'}
    pk_url_kwarg = 'ws_id'

    def get_queryset(self):
        return SoapWebService.objects.get(id=self.kwargs.get('ws_id'))

    def get_context_data(self, *, object_list=None, **kwargs):
        data = super().get_context_data(**kwargs)
        web_service = SoapWebService.objects.get(id=self.kwargs.get('ws_id'))
        data['soapwebservice'] = web_service
        data['ws_id'] = self.kwargs.get('ws_id')
        return data


# This view displays general information on a SOAP Web Service
class DisplaySoapWebServiceView(generic.DetailView):
    template_name = 'SOAP/web_service_info.html'
    model = SoapWebService
    pk_url_kwarg = 'soap_web_service_id'


# This view displays general information on an endpoint
class DisplayEndpointView(generic.DetailView):
    template_name = 'SOAP/endpoint_info.html'
    model = Endpoint
    pk_url_kwarg = 'soap_endpoint_id'


# This view displays information on an operation
class DisplayOperationView(generic.DetailView):
    template_name = 'SOAP/operation_info.html'
    model = Operation
    pk_url_kwarg = 'soap_operation_id'

    def post(self, request, *args, **kwargs):
        operation_id = request.POST['operation_id']
        return redirect('Attacks:attacks_choices', 'soap', self.kwargs.get('ws_id'), operation_id)
