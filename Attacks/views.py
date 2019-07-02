from django.http import HttpResponse, Http404
from django.shortcuts import render, redirect
from django.views import generic
from django.template.loader import get_template
from django_celery_results.models import TaskResult

import os
import time
import datetime
import csv
import json
import html
import plotly
import plotly.graph_objs as go
from ast import literal_eval
from nltk.parse.generate import generate
from nltk import CFG, Nonterminal
from celery.result import AsyncResult
from xhtml2pdf import pisa
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.platypus import *
from reportlab.lib.styles import getSampleStyleSheet

from Attacks.tasks import dos_detection, dynamic_detection_injections
from Attacks import forms
from Attacks.choices import COMMON_VALUES, THRESHHOLD_1_DOS, THRESHHOLD_2_DOS, THRESHHOLD_3_DOS, \
     NUMBER_VALID_REQUESTS_DOS, THRESHHOLD_4_DOS, METHOD_CHOICE, NUMBER_NON_MALICIOUS_REQUESTS, NUMBER_CLUSTERS
from SOAP.models import Operation
from REST.models import Path
from WebService.models import Response, WebService
from WebService.choices import GOOD
from WS_VulnS.settings import BASE_DIR, MEDIA_REPORT_ROOT


def display_pdf(request, **kwargs):
    filename = kwargs.get('filename')
    file_path = os.path.join(MEDIA_REPORT_ROOT, filename)
    if os.path.exists(file_path):
        with open(file_path, 'rb') as file:
            response = HttpResponse(file.read(), content_type="application/pdf")
            response['Content-Disposition'] = 'inline; filename=' + os.path.basename(file_path)
            return response

    raise Http404


# def display_csv(request, **kwargs):
#     filename = kwargs.get('filename')
#     file_path = os.path.join(MEDIA_REPORT_ROOT, filename)
#     if os.path.exists(file_path):
#         with open(file_path, 'rb') as file:
#             response = HttpResponse(file.read(), content_type="text/csv")
#             response['Content-Disposition'] = 'inline; filename=' + os.path.basename(file_path)
#             return response
#
#     raise Http404


# def link_callback(uri, rel):
#     static_url = STATIC_URL
#     static_root = os.path.join(BASE_DIR, 'WebService', 'static')
#     path = ''
#
#     if uri.startswith(static_url):
#         path = os.path.join(static_root, uri.replace(static_url, ''))
#         print(path)
#
#     if not os.path.isfile(path):
#         raise Exception('No such file !')
#     return path


# Ihis class contains functions that generate SQLi patterns from grammar of types : Union, Tautology and Piggy-backed
class GenerateSQLiPatternsFromGrammar(generic.View):
    # This function generates sqli attacks of types : union, tautology and piggy backed
    def get_sql_select_stml_grammar(self, table_name, columns_names, values):
        SQL_ATTACKS_GRAMMAR = '''\
        start_union -> numericContext_union | sQuoteContext_union | dQuoteContext_union 
        start_tautology -> numericContext_tautology | sQuoteContext_tautology | dQuoteContext_tautology 
        start_piggy_backed -> numericContext_piggy_backed | sQuoteContext_piggy_backed | dQuoteContext_piggy_backed 
        numericContext_tautology -> digits wsp tautologyAttack wsp opOr squote | digits parC wsp tautologyAttack wsp opOr parO digits | digits wsp tautologyAttack cmt | digits parC wsp tautologyAttack cmt
        sQuoteContext_tautology -> squote wsp tautologyAttack | squote parC wsp tautologyAttack | squote wsp tautologyAttack cmt | squote parC wsp tautologyAttack cmt
        dQuoteContext_tautology -> dquote wsp tautologyAttack | dquote parC wsp tautologyAttack | dquote wsp tautologyAttack cmt | dquote parC wsp tautologyAttack cmt
        numericContext_union -> digits wsp unionAttack | digits parC wsp union_attack wsp opOr parO digits
        sQuoteContext_union -> squote wsp unionAttack cmt | squote parC wsp unionAttack cmt
        dQuoteContext_union -> dquote wsp unionAttack cmt | dquote parC wsp unionAttack cmt
        numericContext_piggy_backed -> digits wsp piggyAttack | digits parC wsp piggyAttack wsp opOr parO digits
        sQuoteContext_piggy_backed -> squote wsp piggyAttack cmt | squote parC wsp piggyAttack cmt
        dQuoteContext_piggy_backed -> dquote wsp piggyAttack cmt | dquote parC wsp piggyAttack cmt
        unionAttack -> union wsp opSel wsp fakeCols | union wsp unionPostfix opSel wsp fakeCols | union wsp unionPostfix parO opSel wsp fakeCols parC | union wsp opSel wsp all wsp opFrom wsp table
        union -> opUnion | '/*!' opUnion '*/'
        unionPostfix -> 'all' wsp | 'distinct' wsp | wsp
        fakeCols -> null | null comma wsp null | null comma wsp null comma wsp null | null comma wsp null comma wsp null comma wsp null | null comma wsp null comma wsp null comma wsp null comma wsp null
        piggyAttack -> opSem opDel blank opFrom blank table | opSem opDrop blank opFrom blank table | opSem opUpdate blank table blank opSet blank column opEqual value | opSem opInsert blank opInto blank table blank parO column parC blank opValues blank parO value parC | opSem opInsert blank opInto blank table blank parO twoColumns parC blank opValues blank parO twoValues parC | opSem opInsert blank opInto blank table blank parO threeColumns parC blank opValues blank parO threeValues parC | opSem opExec command
        table -> ''' + table_name + '''\n
        column -> ''' + columns_names + '''\n
        twoColumns -> column comma blank column 
        threeColumns -> column comma blank column comma blank column
        twoValues -> value comma blank value 
        threeValues -> value comma blank value comma blank value
        value -> ''' + values + '''\n
        tautologyAttack -> orAttack
        orAttack -> opOr wsp booleanTrueExpr  
        booleanTrueExpr -> parO composedTrue parC | binaryTrue 
        binaryTrue -> parO composedTrue parC wsp opEqual wsp parO composedTrue parC | parO composedFalse parC wsp opEqual wsp parO composedFalse parC | squote char squote opEqual squote char squote | dquote char dquote opEqual dquote char dquote | parO composedFalse parC opLt parO composedTrue parC | parO composedTrue parC opGt parO composedFalse parC | wsp trueConst wsp opLike wsp trueConst | parO composedTrue parC wsp opIs wsp simpleTrue | parO composedFalse parC wsp opIs wsp simpleFalse | parO composedTrue parC opMinus parO composedFalse parC 
        squote -> "'"  
        dquote -> '"'
        parO -> '(' 
        parC -> ')' 
        digits -> '1' | '0' 
        null -> 'null'    
        char -> 'a'
        opEqual -> '='  
        opLt -> '<'  
        opGt -> '>'  
        opLike -> 'like' 
        opIs -> 'is' 
        all -> '*' 
        opMinus -> '-'  
        opOr -> 'or'  
        opAnd -> 'and'
        opSel -> 'select'
        opDel -> 'delete'
        opDrop -> 'drop'
        opInsert -> 'insert'
        opUpdate -> 'update'
        opUnion -> 'union'
        opFrom -> 'from'
        opInto -> 'into'
        opSet -> 'set'
        opValues -> 'values'
        opExec -> 'exec' 
        command -> "master..xp_cmdshell 'ping 127.0.0.1'" ddash | "@rc = master..xp_cmdshell 'dir c:'" opSem ddash | "master..xp_cmdshell 'dir c:'" opSem ddash
        composedTrue -> opSel wsp '4/2 + 1' | '2+1' | '4-1'
        composedFalse -> opSel wsp '2/2' | '1+0' | '2-1'
        trueConst -> 'True'
        simpleTrue -> '3'
        simpleFalse -> '1'
        opSem -> ';'
        comma -> ','
        cmt -> '#' | ddash blank 
        ddash -> '--'
        inlineCmt -> '/**/' 
        blank -> ' '
        wsp -> blank | inlineCmt
        '''
        return SQL_ATTACKS_GRAMMAR

    def gen_sql_stmt_from_grammar(self, start_, num_stmts=None, table_name="table_name", columns_name="columns_names"):
        grammar = CFG.fromstring(self.get_sql_select_stml_grammar(table_name, columns_name, COMMON_VALUES))
        sql_select_stmts = []
        for stmt in generate(grammar, start=Nonterminal(start_), n=num_stmts):
            sql_select_stmts.append(''.join(stmt))
        return sql_select_stmts

    def generate_union(self, num_union=None):
        unions = []
        with open(os.path.join(BASE_DIR, 'Attacks\\Word_Lists\\table_column_names.csv'), "r") as csv_file:
            reader = csv.reader(csv_file, delimiter=",")
            for row in reader:
                unions.append(
                    self.gen_sql_stmt_from_grammar(start_='start_union', num_stmts=num_union, table_name=row[0],
                                                   columns_name='|'.join(row[1:])))
        return unions

    def generate_tautology(self, num_taut=None):
        tautologies = self.gen_sql_stmt_from_grammar(start_='start_tautology', num_stmts=num_taut)
        return tautologies

    def generate_piggy_backed(self, num_piggy=None):
        piggies = []
        with open(os.path.join(BASE_DIR, 'Attacks\\Word_Lists\\table_column_names.csv'), "r") as csv_file:
            reader = csv.reader(csv_file, delimiter=",")
            for row in reader:
                piggies.append(
                    self.gen_sql_stmt_from_grammar(start_='start_piggy_backed', num_stmts=num_piggy, table_name=row[0],
                                                   columns_name='|'.join(row[1:])))
        return piggies


class AttackCreationView(generic.FormView):
    form_class = forms.AttackCreationMultiForm
    template_name = 'Attacks/attacks_choices.html'

    def get(self, request, *args, **kwargs):
        form = self.form_class(kwargs)
        return render(request, self.template_name,
                      {'form': form, 'ws_type': kwargs.get('ws_type'), 'ws_id': kwargs.get('ws_id')})

    def post(self, request, *args, **kwargs):
        form = self.form_class(kwargs_view=kwargs, data=request.POST)
        if form.is_valid():
            selected_attacks = {'Dos': [], 'Inj': []}

            if form.form_classes.get('xmlb'):
                if form['xmlb'].cleaned_data['attack_selected']:
                    xmlbint, xmlbext, bil = form['xmlb'].save()
                    xmlbint.save()
                    xmlbext.save()
                    bil.save()
                    selected_attacks['Dos'].append('xmlb')

            if form.form_classes.get('overxml'):
                if form['overxml'].cleaned_data['attack_selected']:
                    oversized_xml = form['overxml'].save()
                    oversized_xml.save()
                    selected_attacks['Dos'].append('overxml')

            if form.form_classes.get('overpayload'):
                if form['overpayload'].cleaned_data['attack_selected']:
                    oversized_payload = form['overpayload'].save()
                    oversized_payload.save()
                    selected_attacks['Dos'].append('overpayload')

            if form.form_classes.get('xmli'):
                if form['xmli'].cleaned_data['attack_selected']:
                    xml_injection_malformed, xml_injection_replicating, xml_injection_xpath = form['xmli'].save()
                    xml_injection_malformed.save()
                    xml_injection_replicating.save()
                    xml_injection_xpath.save()
                    selected_attacks['Inj'].append('xmli')

            if form['sqli'].cleaned_data['attack_selected']:
                taut, union, piggyb, incq = form['sqli'].save()
                taut.save()
                union.save()
                piggyb.save()
                incq.save()
                selected_attacks['Inj'].append('sqli')

            request.session['selected_attacks'] = selected_attacks

            return redirect('Attacks:attacks_processing', kwargs.get('ws_type'), kwargs.get('ws_id'),
                            kwargs.get('op_id'))

        return render(request, self.template_name,
                      {'form': form, 'ws_type': kwargs.get('ws_type'), 'ws_id': kwargs.get('ws_id')})


class AttacksProcessingView(generic.TemplateView):
    template_name = 'Attacks/attacks_processing.html'

    def get_context_data(self, **kwargs):
        context = super(AttacksProcessingView, self).get_context_data(**kwargs)
        selected_attacks = self.request.session.get('selected_attacks', None)
        ws_type = kwargs.get('ws_type')
        if ws_type == 'rest':
            operation = Path.objects.get(id=kwargs.get('op_id'))
        else:
            operation = Operation.objects.get(id=kwargs.get('op_id'))
        context.update({'selected_attacks': selected_attacks, 'operation_name': operation.name, 'ws_type': ws_type})
        return context

    # Process selected attacks and detection process
    @staticmethod
    def process_attacks(request, **kwargs):
        tasks = {}
        selected_attacks = request.session.get('selected_attacks', None)
        start_time = datetime.datetime.now(datetime.timezone.utc)
        request.session['start_time'] = start_time

        if kwargs.get('ws_type') == 'rest':
            operation = Path.objects.get(id=kwargs.get('op_id'))
            # Injection detection
            if 'sqli' in selected_attacks['Inj']:
                tasks.update({'task_sqli': dynamic_detection_injections.delay(operation.id, 'sqli', 'rest',
                                                                              NUMBER_NON_MALICIOUS_REQUESTS,
                                                                              METHOD_CHOICE, NUMBER_CLUSTERS).id})
            if 'xmli' in selected_attacks['Inj']:
                tasks.update({'task_xmli': dynamic_detection_injections.delay(operation.id, 'xmli', 'rest',
                                                                              NUMBER_NON_MALICIOUS_REQUESTS,
                                                                              METHOD_CHOICE, NUMBER_CLUSTERS).id})
            # DOS detection
            if selected_attacks['Dos']:
                tasks.update({'task_dos': dos_detection.delay(operation.id, selected_attacks['Dos'], 'rest',
                                                              NUMBER_VALID_REQUESTS_DOS, THRESHHOLD_1_DOS,
                                                              THRESHHOLD_2_DOS, THRESHHOLD_3_DOS, THRESHHOLD_4_DOS).id})
        else:
            operation = Operation.objects.get(id=kwargs.get('op_id'))
            # Injection detection
            if 'sqli' in selected_attacks['Inj']:
                tasks.update({'task_sqli': dynamic_detection_injections.delay(operation.id, 'sqli', 'soap',
                                                                              NUMBER_NON_MALICIOUS_REQUESTS,
                                                                              METHOD_CHOICE, NUMBER_CLUSTERS).id})
            if 'xmli' in selected_attacks['Inj']:
                tasks.update({'task_xmli': dynamic_detection_injections.delay(operation.id, 'xmli', 'soap',
                                                                              NUMBER_NON_MALICIOUS_REQUESTS,
                                                                              METHOD_CHOICE, NUMBER_CLUSTERS).id})
                # DOS detection
            if selected_attacks['Dos']:
                tasks.update({'task_dos': dos_detection.delay(operation.id, selected_attacks['Dos'], 'soap',
                                                              NUMBER_VALID_REQUESTS_DOS, THRESHHOLD_1_DOS,
                                                              THRESHHOLD_2_DOS, THRESHHOLD_3_DOS, THRESHHOLD_4_DOS).id})
        return HttpResponse(json.dumps(tasks), content_type='application/json')

    # Get celery task info to update progress bars
    @staticmethod
    def get_task_info(request, **kwargs):
        task_id = request.GET.get('task_id', None)
        if task_id is not None:
            task = AsyncResult(task_id)
            data = {
                'state': task.state,
                'result': task.result,
            }
            return HttpResponse(json.dumps(data), content_type='application/json')
        else:
            return HttpResponse('No job ID given')

    def post(self, request, *args, **kwargs):
        selected_attacks = request.session.get('selected_attacks', None)
        results = {}
        end_times = []

        if 'sqli' in selected_attacks['Inj'] and 'xmli' in selected_attacks['Inj']:
            objects = TaskResult.objects.filter(task_name='Attacks.tasks.dynamic_detection_injections').order_by('-id')[
                      :2]
            for obj in objects:
                if 'xmli' in obj.task_args:
                    results.update({'xmli': obj})
                    end_times.append(obj.date_done)
                elif 'sqli' in obj.task_args:
                    results.update({'sqli': obj})
                    end_times.append(obj.date_done)
        elif 'sqli' in selected_attacks['Inj']:
            obj = TaskResult.objects.filter(
                task_name='Attacks.tasks.dynamic_detection_injections').order_by('-id')[:1].first()
            results.update({'sqli': obj})
            end_times.append(obj.date_done)
        elif 'xmli' in selected_attacks['Inj']:
            obj = TaskResult.objects.filter(
                task_name='Attacks.tasks.dynamic_detection_injections').order_by('-id')[:1].first()
            results.update({'xmli': obj})
            end_times.append(obj.date_done)
        if selected_attacks['Dos']:
            obj = TaskResult.objects.filter(
                task_name='Attacks.tasks.dos_detection').order_by('-id')[:1].first()
            results.update({'dos': obj})
            end_times.append(obj.date_done)

        # Pick the latest task end time
        end_time = max(end_times)
        execution_time = end_time - request.session.get('start_time', None)

        request.session['results'] = results
        request.session['execution_time'] = execution_time

        return redirect('Attacks:report', kwargs.get('ws_type'), kwargs.get('ws_id'), kwargs.get('op_id'))


class ReportView(generic.TemplateView):
    template_name = 'Attacks/report.html'

    def get_context_data(self, **kwargs):
        context = super(ReportView, self).get_context_data(**kwargs)

        ws_type = kwargs.get('ws_type')
        web_service_name = WebService.objects.get(id=kwargs.get('ws_id')).name
        if ws_type == 'rest':
            operation = Path.objects.get(id=kwargs.get('op_id'))
        else:
            operation = Operation.objects.get(id=kwargs.get('op_id'))
        operation_name = operation.name
        context['ws_type'] = ws_type
        context['web_service_name'] = web_service_name
        context['operation_name'] = operation_name
        results = self.request.session.get('results', None)
        execution_time = self.request.session.get('execution_time', None)
        selected_attacks = {'dos': [], 'injections': []}

        nb_tests = 0
        nb_vulnerabilities = 0
        nb_sent_attacks_inj = 0
        nb_sent_attacks_inj_log = 0
        nb_sent_attacks_dos = 0
        nb_valid_requests_inj = 0
        nb_valid_requests_dos = 0

        if 'dos' in results:
            dos_types = literal_eval(results['dos'].task_args)[1]
            selected_attacks['dos'].extend(dos_types)
            results_dos = literal_eval(results['dos'].result)
            context['dos'] = {}
            context['dos']['nb_success_attacks'] = results_dos['nb_success_attacks']
            context['dos']['nb_sent_attacks'] = results_dos['nb_sent_attacks']
            context['dos']['nb_valid_requests'] = results_dos['nb_valid_requests']
            nb_tests += 1
            nb_vulnerabilities += results_dos['nb_success_attacks']
            nb_sent_attacks_dos += results_dos['nb_sent_attacks']
            nb_valid_requests_dos += results_dos['nb_valid_requests']

        if 'xmli' in results:
            selected_attacks['injections'].append('xmli')
            results_xmli = results['xmli'].result
            if 'true' in results_xmli:
                results_xmli = results_xmli.replace('true', 'True')
            if 'false' in results_xmli:
                results_xmli = results_xmli.replace('false', 'False')
            if 'dynamic' in results_xmli:
                results_xmli = results_xmli.replace('dynamic', 'dynamique')
            if 'static' in results_xmli:
                results_xmli = results_xmli.replace('static', 'statique')
            results_xmli = literal_eval(results_xmli)
            context['xmli'] = {}
            if results_xmli['detection_type'] == 'dynamique':
                context['xmli']['nb_success_attacks'] = results_xmli['total_success_attacks']
                context['xmli']['nb_sent_attacks'] = results_xmli['total_sent_attacks']
                context['xmli']['nb_valid_requests'] = results_xmli['nb_valid_requests']
                nb_valid_requests_inj += results_xmli['nb_valid_requests']
                nb_tests += 2
                nb_sent_attacks_inj_log += context['xmli']['nb_sent_attacks'] / 2
                nb_sent_attacks_inj += context['xmli']['nb_sent_attacks']

            else:
                context['xmli']['nb_success_attacks'] = results_xmli['nb_success_attacks']
                context['xmli']['nb_sent_attacks'] = results_xmli['nb_sent_attacks']
                context['xmli']['nb_valid_requests'] = 0
                nb_tests += 1
                nb_sent_attacks_inj_log += context['xmli']['nb_sent_attacks']
                nb_sent_attacks_inj += context['xmli']['nb_sent_attacks']
            if context['xmli']['nb_success_attacks'] > 0:
                if results_xmli['detection_type'] == 'dynamique':
                    context['xmli']['vulns_found'] = results_xmli['total_vulns_found'][operation_name]
                else:
                    context['xmli']['vulns_found'] = results_xmli['vulns_found'][operation_name]
            nb_vulnerabilities += context['xmli']['nb_success_attacks']

        if 'sqli' in results:
            selected_attacks['injections'].append('sqli')
            results_sqli = results['sqli'].result
            if 'true' in results_sqli:
                results_sqli = results_sqli.replace('true', 'True')
            if 'false' in results_sqli:
                results_sqli = results_sqli.replace('false', 'False')
            if 'dynamic' in results_sqli:
                results_sqli = results_sqli.replace('dynamic', 'dynamique')
            if 'static' in results_sqli:
                results_sqli = results_sqli.replace('static', 'statique')
            results_sqli = literal_eval(results_sqli)
            context['sqli'] = {}
            if results_sqli['detection_type'] == 'dynamique':
                context['sqli']['nb_success_attacks'] = results_sqli['total_success_attacks']
                context['sqli']['nb_sent_attacks'] = results_sqli['total_sent_attacks']
                context['sqli']['nb_valid_requests'] = results_sqli['nb_valid_requests']
                nb_valid_requests_inj += results_sqli['nb_valid_requests']
                nb_tests += 2
                nb_sent_attacks_inj_log += context['sqli']['nb_sent_attacks'] / 2
                nb_sent_attacks_inj += context['sqli']['nb_sent_attacks']
            else:
                context['sqli']['nb_success_attacks'] = results_sqli['nb_success_attacks']
                context['sqli']['nb_sent_attacks'] = results_sqli['nb_sent_attacks']
                context['sqli']['nb_valid_requests'] = 0
                nb_tests += 1
                nb_sent_attacks_inj_log += context['sqli']['nb_sent_attacks']
                nb_sent_attacks_inj += context['sqli']['nb_sent_attacks']
            if results_sqli['nb_success_attacks'] > 0:
                if results_sqli['detection_type'] == 'dynamique':
                    context['sqli']['vulns_found'] = results_sqli['total_vulns_found'][operation_name]
                else:
                    context['sqli']['vulns_found'] = results_sqli['vulns_found'][operation_name]
            nb_vulnerabilities += context['sqli']['nb_success_attacks']

        nb_total_requests_log = nb_sent_attacks_inj_log + nb_sent_attacks_dos + nb_valid_requests_inj + nb_valid_requests_dos
        nb_total_requests = nb_sent_attacks_inj + nb_sent_attacks_dos + nb_valid_requests_inj + nb_valid_requests_dos
        context['selected_attacks'] = selected_attacks
        context['execution_time'] = execution_time.total_seconds
        context['nb_tests'] = nb_tests
        context['nb_vulnerabilities'] = nb_vulnerabilities
        context['nb_sent_attacks'] = int(nb_sent_attacks_inj + nb_sent_attacks_dos)
        context['nb_valid_requests'] = nb_valid_requests_inj + nb_valid_requests_dos
        context['nb_total_requests'] = int(nb_total_requests)

        plotly.tools.set_credentials_file(username='Hinata28', api_key='Q3dzZwsFj6oOf6knD6eA')
        if 'dos' in results and 'sqli' not in results and 'xmli' not in results:
            graph = {
                'data': [
                    {
                        'values': [nb_vulnerabilities, nb_valid_requests_dos - nb_vulnerabilities],
                        'labels': [
                            'Attaques réussies',
                            'Attaques non réussies',
                        ],
                        # 'domain': {'column': 0},
                        'hoverinfo': 'label+percent',
                        'hole': .4,
                        'type': 'pie'
                    }],
                'layout': {
                    # 'title': 'Vulnérabilités détectées',
                    'grid': {'rows': 1, 'columns': 1},
                    'margin': go.layout.Margin(b=0, t=10),
                    'height': 300,
                }
            }
        elif 'dos' not in results and ('xmli' in results or 'sqli' in results):
            graph = {
                'data': [
                    {
                        'values': [nb_vulnerabilities, nb_sent_attacks_inj - nb_vulnerabilities],
                        'labels': [
                            'Attaques réussies',
                            'Attaques non réussies',
                        ],
                        # 'domain': {'column': 0},
                        'hoverinfo': 'label+percent',
                        'hole': .4,
                        'type': 'pie'
                    }],
                'layout': {
                    # 'title': 'Vulnérabilités détectées',
                    'grid': {'rows': 1, 'columns': 1},
                    'margin': go.layout.Margin(b=0, t=10),
                    'height': 300,
                }
            }
        elif 'dos' in results and ('xmli' in results or 'sqli' in results):
            graph = {
                'data': [
                    {
                        'values': [nb_vulnerabilities, (nb_sent_attacks_inj + nb_valid_requests_dos) -
                                   nb_vulnerabilities],
                        'labels': [
                            'Attaques réussies',
                            'Attaques non réussies',
                        ],
                        # 'domain': {'column': 0},
                        'hoverinfo': 'label+percent',
                        'hole': .4,
                        'type': 'pie'
                    }],
                'layout': {
                    # 'title': 'Vulnérabilités détectées',
                    'grid': {'rows': 1, 'columns': 1},
                    'margin': go.layout.Margin(b=0, t=10),
                    'height': 300,
                }
            }
        div = plotly.offline.plot(graph, auto_open=False, output_type='div')
        context['report'] = div

        responses = Response.objects.all().order_by('-id')[:nb_total_requests_log]
        log_filename = 'log_' + time.strftime('%Y%m%d_%H%M%S') + '.pdf'
        context['log_filename'] = log_filename
        self.generate_pdf(responses, ws_type, web_service_name, operation_name, log_filename)

        report_filename = 'report_' + time.strftime('%Y%m%d_%H%M%S') + '.pdf'
        context['report_filename'] = report_filename
        # if self.convert_html_to_pdf('Attacks/report.html', context, report_filename):
        #     print('PDF generated !')
        # else:
        #     print('Error while generating PDF !')

        return context

    def convert_html_to_pdf(self, template, data, filename):
        template = get_template(template)
        html_document = template.render(data)
        file = open(os.path.join(MEDIA_REPORT_ROOT, filename), "w+b")
        pdf = pisa.CreatePDF(src=html_document, dest=file)
        file.close()

        return pdf.err

    # def generate_csv(self, data, filename):
    #     csv.register_dialect('dialect', quoting=csv.QUOTE_ALL, skipinitialspace=True)
    #
    #     with open(os.path.join(MEDIA_REPORT_ROOT, filename), 'w') as file:
    #         writer = csv.writer(file, dialect='dialect')
    #         header = ['Num', 'Requête', 'Réponse', 'Code HTTP', 'TFTB', 'Catégorie', 'Attaque']
    #         writer.writerow(header)
    #         i = 0
    #         for resp in data:
    #             if resp.request.category == GOOD:
    #                 row = [i, resp.request.data, resp.content, resp.http_status_code, resp.time_to_first_byte,
    #                        resp.request.category, '']
    #             else:
    #                 row = [i, resp.request.data, resp.content, resp.http_status_code, resp.time_to_first_byte,
    #                        resp.request.category, resp.request.attack_type.name]
    #             writer.writerow(row)
    #             i += 1
    #
    #     file.close()

    def generate_pdf(self, data, ws_type, web_service_name, operation_name, pdf_filename):
        rows = []
        i = 0
        for resp in data:
            if resp.request.category == GOOD:
                rows.append([str(i), resp.request.url, resp.request.http_method, html.escape(resp.request.data[:2000]),
                             html.escape(resp.content), str(resp.http_status_code), str(resp.time_to_first_byte),
                             resp.request.category, '/'])
            else:
                rows.append([str(i), resp.request.url, resp.request.http_method, html.escape(resp.request.data[:2000]),
                             html.escape(resp.content), str(resp.http_status_code), str(resp.time_to_first_byte),
                             resp.request.category, resp.request.attack_type.name])
            i += 1

        elements = []

        styles = getSampleStyleSheet()

        elements.append(Paragraph('Fichier log', styles['Title']))
        elements.append(Spacer(inch, .25 * inch))
        elements.append(Paragraph('Web Service testé', styles['Heading2']))
        elements.append(Paragraph(web_service_name, styles['Normal']))
        if ws_type == 'rest':
            elements.append(Paragraph('Ressource testée', styles['Heading2']))
            elements.append(Paragraph(operation_name, styles['Normal']))
        else:
            elements.append(Paragraph('Opération testée', styles['Heading2']))
            elements.append(Paragraph(operation_name, styles['Normal']))
        elements.append(Spacer(inch, .25 * inch))
        elements.append(Paragraph('Liste des requêtes et réponses', styles['Heading2']))

        for row in rows:
            elements.append(Paragraph('Requête ' + row[0], styles['Heading5']))
            elements.append(Paragraph('URL', styles['Heading5']))
            elements.append(Paragraph(row[1], styles['Normal']))
            elements.append(Paragraph('Méthode HTTP', styles['Heading5']))
            elements.append(Paragraph(row[2], styles['Normal']))
            elements.append(Paragraph('Contenu de la requête', styles['Heading5']))
            elements.append(Paragraph(row[3], styles['Normal']))
            elements.append(Paragraph('Contenu de la réponse', styles['Heading5']))
            elements.append(Paragraph(row[4], styles['Normal']))
            elements.append(Paragraph('Code HTTP', styles['Heading5']))
            elements.append(Paragraph(row[5], styles['Normal']))
            elements.append(Paragraph('TTFB (Time To First Byte)', styles['Heading5']))
            elements.append(Paragraph(row[6], styles['Normal']))
            elements.append(Paragraph('Type de requête', styles['Heading5']))
            elements.append(Paragraph(row[7], styles['Normal']))
            elements.append(Paragraph('Attaque', styles['Heading5']))
            elements.append(Paragraph(row[8], styles['Normal']))
            elements.append(Spacer(inch, .25 * inch))
            elements.append(HRFlowable(dash=[6, 3], color=colors.gray))
            elements.append(Spacer(inch, .25 * inch))

        # Generate PDF
        pdf = SimpleDocTemplate(os.path.join(MEDIA_REPORT_ROOT, pdf_filename), pagesize=A4,
                                rightMargin=10, leftMargin=10, topMargin=20, bottomMargin=20)
        pdf.build(elements)
