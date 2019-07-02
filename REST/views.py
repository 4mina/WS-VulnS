import string
from django.db import transaction, IntegrityError
from django.http import Http404
from lxml import etree
from django.shortcuts import redirect
from django.views.generic import TemplateView, View
import yaml, json, ast, os, magic, re, html
from random import randint, choice, uniform
from prance import ResolvingParser
from time import sleep
from dicttoxml import dicttoxml
from Attacks.models import XMLBombAttack, SQLiAttack, OversizedXMLAttack, OversizedPayloadAttack, XMLiAttack
from REST.models import RestWebService, Path, Method, SwaggerResponse, RestRequest
from urllib.request import urlopen, Request
from urllib.parse import quote
from django.views import generic
from REST.swagger_types import NUMBERS, BOOLEAN, STRING
from WS_VulnS.settings import BASE_DIR
from WebService.choices import HTTP_STATUS_CODES_MEANINGS, GOOD, BAD


# this function changes values of dict one by one and put them in list_new_dicts
def get_all_new_dicts(dict_, new_value):
    list_new_dicts = []
    if isinstance(dict_, dict):
        for k, v in dict_.items():
            if (isinstance(v, dict)) | (isinstance(v, list)):
                # first change the first value then iterate over other values if instance dict or list
                dict_[k] = new_value
                list_new_dicts.append(dict_.copy())
                dict_[k] = v
                # reset the value of the item to the old one so that to have at each time one changing value
                for new_dict in get_all_new_dicts(v, new_value):
                    dict_[k] = new_dict
                    list_new_dicts.append(dict_.copy())
                dict_[k] = v
            else:
                dict_[k] = new_value
                list_new_dicts.append(dict_.copy())
                dict_[k] = v
    elif isinstance(dict_, list):
        for i, v in zip(range(len(dict_)), dict_):
            if (isinstance(dict_[i], dict)) | (isinstance(dict_[i], list)):
                dict_[i] = new_value
                list_new_dicts.append(dict_.copy())
                dict_[i] = v
                for new_dict in get_all_new_dicts(dict_[i], new_value):
                    dict_[i] = new_dict
                    list_new_dicts.append(dict_.copy())
                dict_[i] = v
            else:
                dict_[i] = new_value
                list_new_dicts.append(dict_.copy())
                dict_[i] = v
    return list_new_dicts


# this function replaces all values in dict with new_value :
def replace_all_dict_values(dict_, new_value):
    if isinstance(dict_, dict):
        for k, v in dict_.items():
            if (isinstance(v, dict)) | (isinstance(v, list)):
                dict_[k] = replace_all_dict_values(v, new_value)
            else:
                dict_[k] = new_value
    elif isinstance(dict_, list):
        for i, v in zip(range(len(dict_)), dict_):
            if (isinstance(dict_[i], dict)) | (isinstance(dict_[i], list)):
                dict_[i] = replace_all_dict_values(v, new_value)
            else:
                dict_[i] = new_value
    return dict_


# general function that generate request parameters for non-malicious and malicious ones
# entry_point is the parameter that will hold the malicious content
def generate_request_parameters(method, malicious=False, payload=None, entry_point=None):
    generator = RestValidRequestsGeneration()
    url = generator.generate_url(method.path_id)
    headers = generator.generate_headers(method)
    data = ""
    parameters = ""
    form_data = dict()
    params = method.parameters
    if params:
        for param in params:
            _parameter = generator.generate_parameter(param)
            if "in" in list(param):
                if param["in"] == "path":
                    if (":" in _parameter) & (param != entry_point):
                        _parameter = _parameter.split(":")[1].replace("\"", "")
                    elif malicious & (param == entry_point):
                        _parameter = payload
                    url = re.sub(r"\{(\w+)\}", _parameter, url, 1)
                elif (param["in"] == "query") | ((param['in'] == 'formData') & (
                        headers.get('Content-type') == 'application/x-www-form-urlencoded')):
                    if ":" in _parameter:
                        parameters += "&" + _parameter.replace(":", "=").replace("[", "").replace(",", "&").replace(
                            "]", "").replace("\"", "")
                        if malicious & (param == entry_point):
                            parameters = parameters.replace(parameters.rpartition('&')[2], quote(payload))
                elif param['in'] == "formData":
                    if (not isinstance(_parameter, dict)) & (param != entry_point):
                        _parameter = ast.literal_eval("{" + _parameter + "}")
                    # if param == entry_point then we are necessary in malicious case !
                    elif param == entry_point:
                        if not isinstance(_parameter, dict):
                            _parameter = {'attack': payload}
                        else:
                            #first get the file name and assign to it a new file called attack.txt that will contain the payload
                            _parameter = {list(_parameter.keys())[0]: ('attack.txt', payload)}
                    form_data.update(_parameter)
                elif param['in'] == 'header':
                    if (":" in _parameter) & (param != entry_point):
                        _parameter = "{" + _parameter + "}"
                        headers.update(ast.literal_eval(_parameter))
                    elif param == entry_point:
                        headers.update({'header_attack': payload})
                elif param["in"] == "body":
                    # if array in body then we have to delete the parameter name and have a json array representation
                    if param["type"] == "array":
                        if param.get("xml", ):
                            data = ',{' + _parameter + '}'
                        else:
                            param_name = _parameter.split(":")[0]
                            _parameter = _parameter[param_name.__len__() + 1:]
                            data = ',' + _parameter
                    else:
                        if malicious & (param == entry_point):
                            _parameter = ast.literal_eval("{" + _parameter + "}")
                            data += "," + str(replace_all_dict_values(_parameter, payload))
                        else:
                            data += ",{" + _parameter + "}"
        if data:
            data = data[1:]
            if headers.get("Content-Type") == "application/xml":
                data = dicttoxml(eval(data), attr_type=False, item_func=lambda x: None)
                data = str(data.decode('utf-8')).replace('<None>', '').replace('</None>', '').replace('<root>','').replace('</root>', '')
        elif parameters:
            data = parameters[1:]
    return url, headers, data, form_data


# this function creates Request obj, send req and create response obj
def send_rest_request(method, url, headers, data, files, attack=None, pattern=None):
    request = RestRequest(method_id=method.id, http_method=method.name, url=url, headers=headers, data=data)
    #Non-malicious request
    if attack is None:
        request.category = GOOD
    else:
        request.category = BAD
        request.attack_type = attack
        if attack.family == 'Inj':
            request.pattern = pattern
    if files:
        # because '_io.BufferedReader' object is not serializable
        request.files = str(files)
        response = request.send_request(files)
    else:
        response = request.send_request()
    try:
        with transaction.atomic():
            request.save()
            response.request = request
            response.save()
    except IntegrityError:
        transaction.rollback()
    return response


class RestClientView(TemplateView):
    template_name = 'REST/rest_client.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        try:
            web_service = RestWebService.objects.get(id=self.kwargs.get('pk', ))
            if web_service.description_file:
                try:
                    spec = yaml.load(web_service.description_file.read(), Loader=yaml.Loader)
                except:
                    raise Http404
            else:
                # read YAML file from URL
                try:
                    remote_description_file = urlopen(Request(web_service.description_url))
                    spec = yaml.load(remote_description_file.read())
                # handle the exception better later ... for now just simple 404 if we can't read the specified file
                except:
                    raise Http404
            context = {'restwebservice': json.dumps(spec), 'ws_type': 'rest', 'ws_id': self.kwargs.get('pk', )}
            return context
        # default 404 page for now but we can customize it later !
        except:
            raise Http404


# swagger 2.0
class SwaggerSpecParser(View):

    def parse_parameter(self, param):
        # if parameter in path it has name and in but if in schema it has not !
        parameter = dict()
        if ('name' in list(param)) & ('in' in list(param)):
            parameter.update({'name': param['name'], 'in': param['in']})
        if 'enum' in list(param):
            parameter.update({'enum': param['enum']})
        if 'type' in list(param):
            parameter.update({'type': param['type']})
            # if type is array then items is required
            if param["type"] == "array":
                parameter.update({'items': self.parse_parameter(param["items"])})
                if 'xml' in list(param):
                    parameter.get("items").update({'xml': param['xml']['name']})
                # if collectionFormat is not provided then default is csv. Ex: foo,bar
                if 'collectionFormat' in list(param):
                    parameter.update({'collectionFormat': param['collectionFormat']})
                else:
                    parameter.update({'collectionFormat': 'csv'})
                min_items = 2
                if 'minItems' in list(param):
                    min_items = int(param['minItems'])
                else:
                    if 'maxItems' in list(param):
                        min_items = randint(min_items, int(param['maxItems']))
                parameter.update({'minItems': str(min_items)})
            elif param['type'] == "object":
                properties = []
                if 'properties' in list(param):
                    for key in param['properties'].keys():
                        _property = {'name': key}
                        _property.update(self.parse_parameter(param["properties"][key]))
                        properties.append(_property)
                elif 'additionalProperties' in list(param):
                    _property = self.parse_parameter(param["additionalProperties"])
                    properties.append(_property)
                parameter.update({'properties': properties})
            elif param['type'] in NUMBERS:
                min = 0
                max = 2
                if 'exclusiveMinimum' in list(param):
                    min = int(param['minimum']) + 1
                elif 'minimum' in list(param):
                    min = int(param['minimum'])
                if 'exclusiveMaximum' in list(param):
                    max = int(param['maximum']) - 1
                elif 'maximum' in list(param):
                    max = int(param['maximum'])
                parameter.update({"min": str(min), "max": str(max)})
            # string, boolean or file !
            else:
                #if string : date or date-time are important to know as formats !
                if 'format' in list(param):
                    parameter.update({'format': param['format']})
        # Schema if body parameter
        elif 'schema' in list(param):
            parameter.update(self.parse_parameter(param['schema']))
        if ('xml' in list(param)) & (param.get("type", ) != "array"):
            parameter.update({'xml': param['xml']['name']})
        if 'example' in list(param):
            parameter.update({'example': param['example']})
        return parameter

    def parse_method(self, method, method_name):
        parsed_method = Method(name=method_name.upper())
        if 'summary' in list(method):
            parsed_method.summary = method["summary"]
        if 'description' in list(method):
            parsed_method.description = method["description"]
        if 'consumes' in list(method):
            parsed_method.input_types = method["consumes"]
        if 'produces' in list(method):
            parsed_method.output_types = method["produces"]
        # get parameters of every method of every resource (path)
        if method.get("parameters", ):
            method_parameters = method["parameters"]
            list_parameters = []
            for param in method_parameters:
                parameter = self.parse_parameter(param)
                list_parameters.append(parameter)
            parsed_method.parameters = list_parameters
        return parsed_method

    def parse_swagger(self, web_service_id):
        web_service = RestWebService.objects.get(id=web_service_id)
        if web_service.description_file:
            description_path = web_service.description_file.path.replace("\\", "/")
        else:
            description_path = web_service.description_url
        try:
            parser = ResolvingParser(description_path)
            specification = parser.specification
            try:
                #schemes is a required tag
                base_url = specification.get("schemes", )
                if "https" in base_url:
                    base_url = "https://"
                else:
                    base_url = "http://"
                base_url += specification.get("host", ) + specification.get("basePath", )
                web_service.base_url = base_url
            except:
                print("Expect base URL but not found !")
            # get name, description and different resources (paths) of the REST WS
            web_service.name = specification["info"]["title"]
            web_service.paths = list(specification["paths"])
            if 'description' in list(specification['info']):
                web_service.documentation = specification["info"]["description"]
            # following list will contain all objects to save to the database
            web_service.save()
            for p in specification['paths']:
                path = Path(web_service_id=web_service.id, name=p, methods=[m_.upper() for m_ in specification['paths'][p]])
                methods = []
                resps = {}
                for m in specification['paths'][p]:
                    method = self.parse_method(specification['paths'][p][m], m)
                    methods.append(method)
                    # if security_def_parsed:
                    #     if 'security' in list(specification['paths'][p][m]):
                    #         method.security_section = self.parse_security_section(security_def_parsed, specification['paths'][p][m]['security'])
                    if 'responses' in list(specification['paths'][p][m]):
                        resps_list = []
                        responses = specification['paths'][p][m]['responses']
                        for resp in responses:
                            response = SwaggerResponse(http_code=resp)
                            if 'schema' in responses[resp]:
                                response.schema = self.parse_parameter(responses[resp]["schema"])
                            if 'description' in responses[resp]:
                                response.description = responses[resp]['description']
                            resps_list.append(response)
                        resps.update({method.name: resps_list})
                try:
                    with transaction.atomic():
                        path.save()
                        for m in methods:
                            m.path = path
                            m_name = m.name
                            m.save()
                            if m_name in list(resps):
                                for resp in resps[m_name]:
                                    resp.method = m
                                    resp.save()
                except IntegrityError:
                    transaction.rollback()
        except:
            print("Parsing Error !")
            return False
        return True


class RestValidRequestsGeneration(View):
    def generate_url(self, path_id):
        path = Path.objects.get(id=path_id)
        return path.get_base_url() + path.name

    def generate_headers(self, method):
        headers = dict()
        if method.input_types:
            if not "multipart/form-data" in method.input_types:
                #if xml is accepted then we can test relative attacks !
                if 'application/xml' in method.input_types:
                    headers.update({"Content-Type": "application/xml"})
                else:
                    headers = {"Content-Type": choice(method.input_types)}
        else:
            #sometimes no header is specified but the application needs to have a content-type header
            # so we use the most common for REST Web Service which is JSON !
            headers = {"Content-Type": "application/json"}
        if method.output_types:
            if 'application/xml' in method.output_types:
                headers.update({"accept": "application/xml"})
            else:
                headers = {"accept": choice(method.output_types)}
        else:
            headers.update({"accept": "application/json"})
        return headers

    def generate_number(self, constraints):
        min = constraints['min']
        max = constraints['max']
        number = randint(int(min), int(max))
        # number could be float or double
        if type == 'number':
            number = float(number)
        return "\"" + str(number) + "\""

    def generate_string(self, constraints):
        if 'format' in list(constraints):
            format = constraints['format']
            if format == 'date':
                string = '2017-07-21'
            elif format == 'date-type':
                string = '2017-07-21T17:32:28Z'
            else:
                string = choice(STRING)
        else:
            string = choice(STRING)
        return "\"" + string + "\""

    def choose_random_file(self, type):
        upload_dir = os.path.join(BASE_DIR, 'REST\\Files_to_upload')
        if type == 'text':
            upload_dir = os.path.join(upload_dir, 'Texts')
        elif type == 'image':
            upload_dir = os.path.join(upload_dir, 'Images')
        elif type == 'video':
            upload_dir = os.path.join(upload_dir, 'Videos')
        file = os.path.join(upload_dir, choice(os.listdir(upload_dir)))
        return file

    def generate_parameter(self, constraints):
        parameter = ""
        type = constraints['type']
        if type == "array":
            items = ""
            collection_format = constraints["collectionFormat"]
            min_items = int(constraints["minItems"])
            if collection_format == "ssv":
                for i in range(min_items):
                    items += " " + self.generate_parameter(constraints['items'])
            elif collection_format == "tsv":
                for i in range(min_items):
                    items += "\t" + self.generate_parameter(constraints['items'])
            elif collection_format == "pipes":
                for i in range(min_items):
                    items += "|" + self.generate_parameter(constraints['items'])
            # CSV by default : foo,bar,baz (or case of multi but the comma will be just a temporary separator)
            else:
                for i in range(min_items):
                    items += "," + self.generate_parameter(constraints['items'])
            items = items[1:]
            if "name" in list(constraints):
                # if collection_format = multi : same variable but with multiple values (query and formData requests)
                # foo=value&foo=another_value
                parameter = "\"" + constraints['name'] + "\":[" + items + ']'
            else:
                parameter = '[' + items + ']'
        elif type == "object":
            properties = ""
            if 'properties' in list(constraints):
                for prop in constraints['properties']:
                    properties += "," + self.generate_parameter(prop)
            elif 'additionalProperties' in list(constraints):
                for prop in constraints['additionalProperties'].keys():
                    properties += "," + self.generate_parameter(prop)
            properties = properties[1:]
            if "name" in list(constraints):
                parameter = "\"" + constraints['name'] + "\":{" + properties + '}'
            else:
                parameter = '{' + properties + '}'
        elif type == "file":
            #check input types to see if png
            file_name = self.choose_random_file("text")
            file_type = magic.from_buffer(open(file_name, 'rb').read(1024), mime=True)
            if 'name' in list(constraints):
                parameter = {constraints['name']: (file_name, open(file_name, 'rb'), file_type, {'type': file_type})}
            else:
                parameter = {'file': (file_name, open(file_name, 'rb'), file_type, {'type': file_type})}
        else:
            if 'example' in list(constraints):
                if 'name' in list(constraints):
                    parameter = "\"" + constraints['name'] + "\":\"" + constraints['example'] + "\""
                else:
                    parameter = "\"" + constraints['example'] + "\""
            elif 'enum' in list(constraints):
                if 'name' in list(constraints):
                    parameter = "\"" + constraints['name'] + "\":\"" + str(choice(constraints['enum'])) + "\""
                else:
                    parameter = "\"" + str(choice(constraints['enum'])) + "\""
            else:
                if type in NUMBERS:
                    if 'name' in list(constraints):
                        parameter = "\"" + constraints['name'] + "\":" + self.generate_number(constraints)
                    else:
                        parameter = self.generate_number(constraints)
                elif type == 'string':
                    if 'name' in list(constraints):
                        parameter = "\"" + constraints['name'] + '\":' + self.generate_string(constraints)
                    else:
                        parameter = self.generate_string(constraints)
                elif type == 'boolean':
                    if 'name' in list(constraints):
                        parameter = "\"" + constraints['name'] + '\":\"' + str(choice(BOOLEAN)) + "\""
                    else:
                        parameter = str(choice(BOOLEAN))
        if "xml" in list(constraints):
            if not constraints.get("name", ):
                parameter = "{\"" + constraints["xml"] + "\":" + parameter + "}"
            else:
                parameter = parameter.replace(constraints["name"], constraints["xml"], 1)
        return parameter

    #generate num_req valid requests for every method in path
    def send_valid_request(self, path, num_req, simulate=False):
        responses = {}
        for method in path.method_set.all():
            responses.update({method.name: []})
            for i in range(num_req):
                url, headers, data, files = generate_request_parameters(method)
                (responses[method.name]).append(send_rest_request(method, url, headers, data, files))
                if simulate:
                    sleep(5)
        return responses

    def send_fuzzed_request(self, path, num_req):
        responses = {}
        for method in path.method_set.all():
            responses.update({method.name: []})
            for i in range(num_req):
                i = randint(0, 2)
                if i == 0:
                    caracters = string.ascii_letters + string.digits
                    fuzzed_data = ''.join(choice(caracters) for i in range(randint(0, 500)))
                elif i == 1:
                    fuzzed_data = uniform(0, 1000)
                else:
                    fuzzed_data = randint(0, 1000)
                if method.parameters:
                    param_number = randint(0, len(method.parameters) - 1)
                    url, headers, data, files = generate_request_parameters(method, True, str(fuzzed_data),
                                                                            method.parameters[param_number])
                else:
                    url, headers, data, files = generate_request_parameters(method, True)
                    data = str(fuzzed_data)
                (responses[method.name]).append(send_rest_request(method, url, headers, data, files))
        return responses


class SwaggerExplorerView(generic.ListView):
    template_name = 'REST/rest_explorer.html'
    context_object_name = 'restwebservice'
    extra_context = {'ws_type': 'rest'}

    def get_queryset(self):
        try:
            web_service = RestWebService.objects.get(id=self.kwargs.get('pk', ))
            # this Web service has not been parsed yet !
            if not Path.objects.filter(web_service_id=web_service.id):
                parser = SwaggerSpecParser()
                parser.parse_swagger(web_service.id)
            return web_service
        except:
            raise Http404

    def get_context_data(self, *, object_list=None, **kwargs):
        try:
            data = super().get_context_data(**kwargs)
            data['ws_id'] = self.kwargs.get('pk', )
            data['restwebservice'] = RestWebService.objects.get(id=data['ws_id'])
            return data
        except:
            raise Http404


class DisplayRestWebService(generic.DetailView):
    model = RestWebService
    template_name = 'REST/rest_web_service_info.html'


class DisplayResource(generic.DetailView):
    model = Path
    template_name = 'REST/resource_info.html'

    def get_context_data(self, **kwargs):
        data = super().get_context_data(**kwargs)
        path = Path.objects.get(id=self.kwargs.get('pk', ))
        data['method'] = Method.objects.get(path_id=path.id, name=path.methods[0])
        return data

    def post(self, request, *args, **kwargs):
        path_id = request.POST["path_id"]
        return redirect('Attacks:attacks_choices', 'rest', self.kwargs.get('ws_id', ), path_id)


class DisplayMethod(generic.DetailView):
    model = Method
    template_name = 'REST/method_info.html'


class RestMaliciousRequestsGeneration(View):
    def send_malicious_request(self, selected_attacks, path):
        responses = {}
        if 'xmlb' in selected_attacks:
            responses.update({"xmlb":{}})
            # get three latest xmlb objects known that there are 3 types of XML Bomb
            last_three_xmlb = XMLBombAttack.objects.all().order_by('-id')[:3]
            # we send the 3 types of xml bomb for every parameter in the tested path
            for method in path.method_set.all():
                if (bool(method.parameters)) & (method in path.get_methods_accept_xml()):
                    responses['xmlb'].update({method.name: []})
                    for param in method.parameters:
                        for xmlb in last_three_xmlb:
                            # in case of xmlbomb and all other attacks using XML we append the payload to valid one!
                            # first we generate the valid request parameters
                            url, headers, data, files = generate_request_parameters(method)
                            # we add the DTD to the generated data and then we call the entity in the body the XML data
                            data = data.split(">", 1)[0] + ">" + xmlb.payload + data.split(">",1)[1]
                            (responses["xmlb"][method.name]).append(send_rest_request(method, url, headers,
                                                                                      data, files, xmlb))
                            #sleep(20)
        if 'overxml' in selected_attacks:
            responses.update({'overxml': {}})
            last_overxml = OversizedXMLAttack.objects.latest(field_name='id')
            for method in path.method_set.all():
                if (bool(method.parameters)) & (method in path.get_methods_accept_xml()):
                    responses['overxml'].update({method.name: []})
                    for param in method.parameters:
                        url, headers, data, files = generate_request_parameters(method)
                        data_tree = etree.fromstring(data.encode())
                        if last_overxml.type == "LongNames":
                            data_tree.append(etree.fromstring("<overxml_payload>oversized_xml</overxml_payload>"))
                            data = etree.tostring(data_tree).decode()
                            data = re.sub('overxml_payload', '{oversized_payload}'.format(
                                oversized_payload=last_overxml.payload), data)
                        #OverAttrContent
                        else:
                            data_tree.append(etree.fromstring("<overxml_payload overxml_attr=\"\"></overxml_payload>"))
                            data = etree.tostring(data_tree).decode()
                            data = re.sub('overxml_attr=""', 'overxml_attr="{oversized_payload}"'.format(
                                oversized_payload=last_overxml.payload), data)
                        (responses['overxml'][method.name]).append(send_rest_request(method, url, headers,
                                                                                     data, files, last_overxml))
                        #sleep(20)
        if 'overpayload' in selected_attacks:
            responses.update({'overpayload': {}})
            last_overpayload = OversizedPayloadAttack.objects.latest(field_name='id')
            for method in path.method_set.all():
                if (bool(method.parameters)) & (method in path.get_methods_accept_xml()):
                    responses['overpayload'].update({method.name: []})
                    for param in method.parameters:
                        url, headers, data, files = generate_request_parameters(method)
                        data_tree = etree.fromstring(data.encode())
                        if last_overpayload.type == "Body":
                            data_tree.append(etree.fromstring("<overxml_payload>oversized_payload</overxml_payload>"))
                            data = etree.tostring(data_tree).decode()
                            data = re.sub('oversized_payload','{oversized_payload}'.format(
                                oversized_payload=last_overpayload.payload), data)
                            (responses["overpayload"][method.name]).append(send_rest_request(method, url, headers,
                                                                                             data, files, last_overpayload))
                            #sleep(20)
        if 'sqli' in selected_attacks:
            responses.update({"sqli":{}})
            last_four_sqli = SQLiAttack.objects.all().order_by('-id')[:4]
            for method in path.method_set.all():
                if method.parameters:
                    responses['sqli'].update({method.name: []})
                    for param in method.parameters:
                        for sqli in last_four_sqli:
                            for pattern in sqli.patterns:
                                url, headers, data, files = generate_request_parameters(method, True, pattern, param)
                                (responses["sqli"][method.name]).append(send_rest_request(method, url, headers,
                                                                                          data, files, sqli, pattern))
        if 'xmli' in selected_attacks:
            responses.update({'xmli': {}})
            last_three_xmli = XMLiAttack.objects.all().order_by('-id')[:3]
            for method in path.method_set.all():
                if (bool(method.parameters)) & (method in path.get_methods_accept_xml()):
                    responses['xmli'].update({method.name: []})
                    for param in method.parameters:
                        for xmli in last_three_xmli:
                            url, headers, data, files = generate_request_parameters(method)
                            # choose random tag (rand element in the XML data) and inject the payload
                            if xmli.type == 'Malformed' or xmli.type == 'XPath':
                                for pattern in xmli.patterns:
                                    data_tree = etree.fromstring(data.encode())
                                    # get random element
                                    element_index = randint(0, len(data_tree) - 1)
                                    data_tree[element_index].text = pattern
                                    data_ = html.unescape(etree.tostring(data_tree).decode())
                                    (responses["xmli"][method.name]).append(send_rest_request(method, url, headers,
                                                                                              data_, files, xmli, pattern))
                            # replicating
                            else:
                                for pattern in xmli.patterns:
                                    data_tree = etree.fromstring(data.encode())
                                    # get random element
                                    element_index = randint(0, len(data_tree) - 1)
                                    # duplicate that element
                                    duplicate_element = etree.Element(data_tree[element_index].tag)
                                    duplicate_element.text = pattern
                                    # insert it next to the initial element
                                    data_tree[element_index].addnext(duplicate_element)
                                    data_ = html.unescape(etree.tostring(data_tree).decode())
                                    (responses["xmli"][method.name]).append(send_rest_request(method, url, headers,
                                                                                              data_, files, xmli, pattern))
        return responses
