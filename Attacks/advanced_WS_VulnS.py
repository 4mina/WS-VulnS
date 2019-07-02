import datetime
import html
import os
from WS_VulnS.settings import BASE_DIR
from configparser import ConfigParser
from time import sleep, strftime
from django_celery_results.models import TaskResult
from ast import literal_eval
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.platypus import *
from reportlab.lib.styles import getSampleStyleSheet

from Attacks.tasks import dos_detection, dynamic_detection_injections
from SOAP.models import Operation
from REST.models import Path
from WebService.models import Response
from WebService.choices import GOOD
from WS_VulnS.settings import MEDIA_REPORT_ROOT


def generate_pdf(data, ws_type, web_service_name, operation_name, pdf_filename):
    rows = []
    i = 0
    for resp in data:
        if resp.request.category == GOOD:
            rows.append([str(i), resp.request.url, resp.request.http_method, html.escape(resp.request.data)[0:2000],
                         html.escape(resp.content), str(resp.http_status_code), str(resp.time_to_first_byte),
                         resp.request.category, '/'])
        else:
            rows.append([str(i), resp.request.url, resp.request.http_method, html.escape(resp.request.data)[0:2000],
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


def write_results_files(attack, ws_type, operation_name, attack_context, execution_time, folder_name, text_filename):
    with open(os.path.join(MEDIA_REPORT_ROOT, folder_name, text_filename), 'w') as file:
        if ws_type == 'rest':
            file.write('Resource :\n')
        else:
            file.write('Operation : \n')
        file.write(operation_name)
        file.write('\n\n' + '*' * 30 + 'Result ' + attack + '*' * 30 + ':\n\n')
        file.write('Result :\n')
        file.write(str(attack_context))
        file.write('Execution time :\n')
        file.write(str(execution_time.total_seconds()) + ' seconds')
    file.close()


def generate_reports(selected_attacks, ws_type, web_service_name, operation_name, start_times, folder_names):
    results = {}
    if 'sqli' in selected_attacks['Inj'] and 'xmli' in selected_attacks['Inj']:
        objects = TaskResult.objects.filter(task_name='Attacks.tasks.dynamic_detection_injections').order_by('-id')[:2]
        for obj in objects:
            if 'xmli' in obj.task_args:
                results.update({'xmli': obj})
                xmli_folder_name = folder_names[0]
                xmli_execution_time = obj.date_done - start_times[0]
            elif 'sqli' in obj.task_args:
                results.update({'sqli': obj})
                sqli_folder_name = folder_names[1]
                sqli_execution_time = obj.date_done - start_times[1]
    elif 'xmli' in selected_attacks['Inj']:
        obj = TaskResult.objects.filter(
            task_name='Attacks.tasks.dynamic_detection_injections').order_by('-id')[:1].first()
        results.update({'xmli': obj})
        xmli_execution_time = obj.date_done - start_times[0]
        xmli_folder_name = folder_names[0]
    elif 'sqli' in selected_attacks['Inj']:
        obj = TaskResult.objects.filter(
            task_name='Attacks.tasks.dynamic_detection_injections').order_by('-id')[:1].first()
        results.update({'sqli': obj})
        sqli_execution_time = obj.date_done - start_times[1]
        sqli_folder_name = folder_names[1]
    if selected_attacks['Dos']:
        obj = TaskResult.objects.filter(
            task_name='Attacks.tasks.dos_detection').order_by('-id')[:1].first()
        results.update({'dos': obj})
        dos_execution_time = obj.date_done - start_times[2]
        dos_folder_name = folder_names[2]

    nb_tests = 0
    nb_vulnerabilities = 0
    nb_sent_attacks = 0
    nb_valid_requests = 0

    context = {}

    if 'dos' in results:
        results_dos = literal_eval(results['dos'].result)
        context['dos'] = {}
        context['dos'].update({'nb_success_attacks': results_dos['nb_success_attacks']})
        context['dos'].update({'nb_sent_attacks': results_dos['nb_sent_attacks']})
        context['dos'].update({'nb_valid_requests': results_dos['nb_valid_requests']})
        context['dos'].update({'average_normal_ttfb': results_dos['average_normal_ttfb']})
        nb_tests += 1
        nb_vulnerabilities += results_dos['nb_success_attacks']
        nb_sent_attacks += results_dos['nb_sent_attacks']
        nb_valid_requests += results_dos['nb_valid_requests']

    if 'xmli' in results:
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
        print("xmli results: ", results_xmli)
        context['xmli'] = {}
        if results_xmli['detection_type'] == 'dynamique':
            context['xmli']['nb_success_attacks'] = results_xmli['total_success_attacks']
            context['xmli']['nb_sent_attacks'] = results_xmli['total_sent_attacks']
            context['xmli']['nb_valid_requests'] = results_xmli['nb_valid_requests']
            nb_valid_requests += results_xmli['nb_valid_requests']
            nb_tests += 2
        else:
            context['xmli']['nb_success_attacks'] = results_xmli['nb_success_attacks']
            context['xmli']['nb_sent_attacks'] = results_xmli['nb_sent_attacks']
            context['xmli']['nb_valid_requests'] = 0
            nb_tests += 1
        if context['xmli']['nb_success_attacks'] > 0:
            if results_xmli['detection_type'] == 'dynamique':
                context['xmli']['vulns_found'] = results_xmli['total_vulns_found'][operation_name]
                context['xmli']['vulns_found_dynamic'] = results_xmli["vulns_found"][operation_name]
                context['xmli']['vulns_found_static'] = results_xmli["vulns_found_statique"][operation_name]
                nb_sent_attacks += context['xmli']['nb_sent_attacks'] / 2
            else:
                context['xmli']['vulns_found_static'] = results_xmli['vulns_found'][operation_name]
                nb_sent_attacks += context['xmli']['nb_sent_attacks']
        nb_vulnerabilities += context['xmli']['nb_success_attacks']

    if 'sqli' in results:
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
            nb_valid_requests += results_sqli['nb_valid_requests']
            nb_tests += 2
        else:
            context['sqli']['nb_success_attacks'] = results_sqli['nb_success_attacks']
            context['sqli']['nb_sent_attacks'] = results_sqli['nb_sent_attacks']
            context['sqli']['nb_valid_requests'] = 0
            nb_tests += 1
        if results_sqli['nb_success_attacks'] > 0:
            if results_sqli['detection_type'] == 'dynamique':
                context['sqli']['vulns_found'] = results_sqli['total_vulns_found'][operation_name]
                context['sqli']['vulns_found_dynamic'] = results_sqli["vulns_found"][operation_name]
                context['sqli']['vulns_found_static'] = results_sqli["vulns_found_statique"][operation_name]
                nb_sent_attacks += context['sqli']['nb_sent_attacks'] / 2
            else:
                context['sqli']['vulns_found_static'] = results_sqli['vulns_found'][operation_name]
                nb_sent_attacks += context['sqli']['nb_sent_attacks']
        nb_vulnerabilities += context['sqli']['nb_success_attacks']

    nb_total_requests = nb_sent_attacks + nb_valid_requests
    context.update({'nb_tests': nb_tests})
    context.update({'nb_vulnerabilities': nb_vulnerabilities})
    context.update({'nb_sent_attacks': nb_sent_attacks})
    context.update({'nb_valid_requests': nb_valid_requests})
    context.update({'nb_total_requests': nb_total_requests})

    if ws_type == 'rest':
        if len(operation_name.split('/')) > 2:
            text_filename = 'Test_' + operation_name.split("/")[1] + '_' + operation_name.split('/')[2] + '.txt'
        else:
            text_filename = 'Test_' + operation_name.split("/")[1] + '.txt'
    else:
        text_filename = 'Test_' + operation_name + '.txt'
    responses = Response.objects.all().order_by('-id')[:nb_total_requests]
    log_filename = 'log_' + strftime('%Y%m%d_%H%M%S') + '.pdf'
    context['log_filename'] = log_filename

    for attack in selected_attacks:
        if attack == 'Inj':
            for attack__ in selected_attacks[attack]:
                if attack__ == "sqli":
                    write_results_files("sqli", ws_type, operation_name, context['sqli'], sqli_execution_time,
                                        sqli_folder_name, text_filename)
                    generate_pdf(responses, ws_type, web_service_name, operation_name, log_filename)
                elif attack__ == 'xmli':
                    write_results_files("xmli", ws_type, operation_name, context['xmli'], xmli_execution_time,
                                        xmli_folder_name, text_filename)
                    generate_pdf(responses, ws_type, web_service_name, operation_name, log_filename)
        elif attack == 'Dos' and len(selected_attacks['Dos']) > 0:
            write_results_files("Dos", ws_type, operation_name, context['dos'], dos_execution_time,
                                dos_folder_name, text_filename)
            generate_pdf(responses, ws_type, web_service_name, operation_name, log_filename)


''' MAIN '''

config_parser = ConfigParser()
config_parser.read(os.path.join(BASE_DIR, 'Attacks', 'advanced_WS_VulnS.ini'))
SELECTED_ATTACKS = literal_eval(config_parser['SELECTED_ATTACKS_CONFIG']['SELECTED_ATTACKS'])
WS_TYPE = config_parser['WEB_SERVICE_CONFIG']['WEB_SERVICE_TYPE']
# DOS
NUMBER_VALID_REQUESTS_DOS = int(config_parser['DOS_CONFIG']['NUMBER_VALID_REQUESTS_DOS'])
THRESHHOLD_1_DOS = int(config_parser['DOS_CONFIG']['THRESHHOLD_1_DOS'])
THRESHHOLD_2_DOS = int(config_parser['DOS_CONFIG']['THRESHHOLD_2_DOS'])
THRESHHOLD_3_DOS = int(config_parser['DOS_CONFIG']['THRESHHOLD_3_DOS'])
THRESHHOLD_4_DOS = int(config_parser['DOS_CONFIG']['THRESHHOLD_4_DOS'])
# Injections
NUMBER_VALID_REQUESTS_INJECTIONS = int(config_parser['INJECTIONS_CONFIG']['NUMBER_VALID_REQUESTS_INJECTIONS'])
NUMBER_CLUSTERS = int(config_parser['INJECTIONS_CONFIG']['NUMBER_CLUSTERS'])
METHODS_CHOICE = literal_eval(config_parser['INJECTIONS_CONFIG']['METHODS_CHOICE'])

if WS_TYPE == 'soap':
    operation = Operation.objects.get(id=config_parser['WEB_SERVICE_CONFIG']['WEB_SERVICE_OPERATION_ID'])
    ws_name = operation.endpoint.web_service.name
else:
    operation = Path.objects.get(id=config_parser['WEB_SERVICE_CONFIG']['WEB_SERVICE_OPERATION_ID'])
    ws_name = operation.web_service.name

# first we start all selected attacks detections at the same time (in parallel)
if len(SELECTED_ATTACKS['Dos']) > 0:
    result_folder_name_dos = ws_name + '_DOS_Test_' + str(NUMBER_VALID_REQUESTS_INJECTIONS) + '_' + \
                         str(THRESHHOLD_1_DOS) + '_' + str(THRESHHOLD_2_DOS) + '_' + str(THRESHHOLD_3_DOS) + \
                         '_' + str(THRESHHOLD_4_DOS)
    folder_path = os.path.join(MEDIA_REPORT_ROOT, result_folder_name_dos)
    if not os.path.exists(folder_path):
        os.mkdir(folder_path)
    job_dos_start_time = datetime.datetime.now(datetime.timezone.utc)
    job_dos = dos_detection.delay(operation.id, SELECTED_ATTACKS['Dos'], WS_TYPE, NUMBER_VALID_REQUESTS_DOS,
                                  THRESHHOLD_1_DOS, THRESHHOLD_2_DOS, THRESHHOLD_3_DOS, THRESHHOLD_4_DOS)

if 'sqli' in SELECTED_ATTACKS['Inj']:
    if 'preprocessing_method_1' in METHODS_CHOICE:
        if 'k_means' in METHODS_CHOICE['preprocessing_method_1']:
            result_folder_name_sqli = ws_name + '_SQLI_Test_' + str(NUMBER_VALID_REQUESTS_INJECTIONS) + \
                                      '_METHOD_1_K_MEANS_' + str(NUMBER_CLUSTERS)
            folder_path = os.path.join(MEDIA_REPORT_ROOT, result_folder_name_sqli)
            if not os.path.exists(folder_path):
                os.mkdir(folder_path)
            job_sqli_start_time = datetime.datetime.now(datetime.timezone.utc)
            job_sqli = dynamic_detection_injections.delay(operation.id, 'sqli', WS_TYPE,
                                                          NUMBER_VALID_REQUESTS_INJECTIONS,
                                                          METHODS_CHOICE, NUMBER_CLUSTERS)

        elif 'spherical_k_means' in METHODS_CHOICE['preprocessing_method_1']:
            result_folder_name_sqli = ws_name + '_SQLI_Test_' + str(NUMBER_VALID_REQUESTS_INJECTIONS) + \
                                 '_METHOD_1_SPHERICAL_K_MEANS_' + str(NUMBER_CLUSTERS)
            folder_path = os.path.join(MEDIA_REPORT_ROOT, result_folder_name_sqli)
            if not os.path.exists(folder_path):
                os.mkdir(folder_path)
            job_sqli_start_time = datetime.datetime.now(datetime.timezone.utc)
            job_sqli = dynamic_detection_injections.delay(operation.id, 'sqli', WS_TYPE,
                                                          NUMBER_VALID_REQUESTS_INJECTIONS, METHODS_CHOICE,
                                                          NUMBER_CLUSTERS)

        elif 'cah' in METHODS_CHOICE['preprocessing_method_1']:
            result_folder_name_sqli = ws_name + '_SQLI_Test_' + str(NUMBER_VALID_REQUESTS_INJECTIONS) + '_METHOD_1_CAH'
            folder_path = os.path.join(MEDIA_REPORT_ROOT, result_folder_name_sqli)
            if not os.path.exists(folder_path):
                os.mkdir(folder_path)
            job_sqli_start_time = datetime.datetime.now(datetime.timezone.utc)
            job_sqli = dynamic_detection_injections.delay(operation.id, 'sqli', WS_TYPE,
                                                          NUMBER_VALID_REQUESTS_INJECTIONS, METHODS_CHOICE)

        elif 'hybrid' in METHODS_CHOICE['preprocessing_method_1']:
            result_folder_name_sqli = ws_name + '_SQLI_Test_' + str(NUMBER_VALID_REQUESTS_INJECTIONS) \
                                      + '_METHOD_1_HYBRID'
            folder_path = os.path.join(MEDIA_REPORT_ROOT, result_folder_name_sqli)
            if not os.path.exists(folder_path):
                os.mkdir(folder_path)
            job_sqli_start_time = datetime.datetime.now(datetime.timezone.utc)
            job_sqli = dynamic_detection_injections.delay(operation.id, 'sqli', WS_TYPE,
                                                          NUMBER_VALID_REQUESTS_INJECTIONS, METHODS_CHOICE)

    elif 'preprocessing_method_2' in METHODS_CHOICE:
        if 'cah' in METHODS_CHOICE['preprocessing_method_2']:
            result_folder_name_sqli = ws_name + '_SQLI_Test_' + str(NUMBER_VALID_REQUESTS_INJECTIONS) + '_METHOD_2_CAH'
            folder_path = os.path.join(MEDIA_REPORT_ROOT, result_folder_name_sqli)
            if not os.path.exists(folder_path):
                os.mkdir(folder_path)
            job_sqli_start_time = datetime.datetime.now(datetime.timezone.utc)
            job_sqli = dynamic_detection_injections.delay(operation.id, 'sqli', WS_TYPE,
                                                          NUMBER_VALID_REQUESTS_INJECTIONS, METHODS_CHOICE)

if 'xmli' in SELECTED_ATTACKS['Inj']:
    if 'preprocessing_method_1' in METHODS_CHOICE:
        if 'k_means' in METHODS_CHOICE['preprocessing_method_1']:
            result_folder_name_xmli = ws_name + '_XMLI_Test_' + str(NUMBER_VALID_REQUESTS_INJECTIONS) + \
                                      '_METHOD_1_K_MEANS_' + str(NUMBER_CLUSTERS)
            folder_path = os.path.join(MEDIA_REPORT_ROOT, result_folder_name_xmli)
            if not os.path.exists(folder_path):
                os.mkdir(folder_path)
            job_xmli_start_time = datetime.datetime.now(datetime.timezone.utc)
            job_xmli = dynamic_detection_injections.delay(operation.id, 'xmli', WS_TYPE,
                                                          NUMBER_VALID_REQUESTS_INJECTIONS, METHODS_CHOICE,
                                                          NUMBER_CLUSTERS)

        elif 'spherical_k_means' in METHODS_CHOICE['preprocessing_method_1']:
            result_folder_name_xmli = ws_name + '_XMLI_Test_' + str(NUMBER_VALID_REQUESTS_INJECTIONS) + \
                                 '_METHOD_1_SPHERICAL_K_MEANS_' + str(NUMBER_CLUSTERS)
            folder_path = os.path.join(MEDIA_REPORT_ROOT, result_folder_name_xmli)
            if not os.path.exists(folder_path):
                os.mkdir(folder_path)
            job_xmli_start_time = datetime.datetime.now(datetime.timezone.utc)
            job_xmli = dynamic_detection_injections.delay(operation.id, 'xmli', WS_TYPE,
                                                          NUMBER_VALID_REQUESTS_INJECTIONS, METHODS_CHOICE,
                                                          NUMBER_CLUSTERS)

        elif 'cah' in METHODS_CHOICE['preprocessing_method_1']:
            result_folder_name_xmli = ws_name + '_XMLI_Test_' + str(NUMBER_VALID_REQUESTS_INJECTIONS) + '_METHOD_1_CAH'
            folder_path = os.path.join(MEDIA_REPORT_ROOT, result_folder_name_xmli)
            if not os.path.exists(folder_path):
                os.mkdir(folder_path)
            job_xmli_start_time = datetime.datetime.now(datetime.timezone.utc)
            job_xmli = dynamic_detection_injections.delay(operation.id, 'xmli', WS_TYPE,
                                                          NUMBER_VALID_REQUESTS_INJECTIONS, METHODS_CHOICE)

        elif 'hybrid' in METHODS_CHOICE['preprocessing_method_1']:
            result_folder_name_xmli = ws_name + '_XMLI_Test_' + str(NUMBER_VALID_REQUESTS_INJECTIONS) + \
                                      '_METHOD_1_HYBRID'
            folder_path = os.path.join(MEDIA_REPORT_ROOT, result_folder_name_xmli)
            if not os.path.exists(folder_path):
                os.mkdir(folder_path)
            job_xmli_start_time = datetime.datetime.now(datetime.timezone.utc)
            job_xmli = dynamic_detection_injections.delay(operation.id, 'xmli', WS_TYPE,
                                                          NUMBER_VALID_REQUESTS_INJECTIONS, METHODS_CHOICE)

    elif 'preprocessing_method_2' in METHODS_CHOICE:
        if 'cah' in METHODS_CHOICE['preprocessing_method_2']:
            result_folder_name_xmli = ws_name + '_XMLI_Test_' + str(NUMBER_VALID_REQUESTS_INJECTIONS) + '_METHOD_2_CAH'
            folder_path = os.path.join(MEDIA_REPORT_ROOT, result_folder_name_xmli)
            if not os.path.exists(folder_path):
                os.mkdir(folder_path)
            job_xmli_start_time = datetime.datetime.now(datetime.timezone.utc)
            job_xmli = dynamic_detection_injections.delay(operation.id, 'xmli', WS_TYPE,
                                                          NUMBER_VALID_REQUESTS_INJECTIONS, METHODS_CHOICE)

# second we generate the report for the selected attacks

# wait for all jobs to finish
jobs = True
if len(SELECTED_ATTACKS['Dos']) > 0:
    if 'sqli' in SELECTED_ATTACKS['Inj'] and 'xmli' in SELECTED_ATTACKS['Inj']:
        while not job_dos.ready() or not job_sqli.ready() or not job_xmli.ready():
            sleep(0.5)
        jobs_start_times = [job_xmli_start_time, job_sqli_start_time, job_dos_start_time]
        results_folder_names = [result_folder_name_xmli, result_folder_name_sqli, result_folder_name_dos]
    elif 'sqli' in SELECTED_ATTACKS['Inj']:
        while not job_dos.ready() or not job_sqli.ready():
            sleep(0.5)
        jobs_start_times = [None, job_sqli_start_time, result_folder_name_dos]
        results_folder_names = [None, result_folder_name_sqli, result_folder_name_dos]
    elif 'xmli' in SELECTED_ATTACKS['Inj']:
        while not job_dos.ready() or not job_xmli.ready():
            sleep(0.5)
        jobs_start_times = [job_xmli_start_time, None, job_dos_start_time]
        results_folder_names = [result_folder_name_xmli, None, result_folder_name_dos]
    else:
        while not job_dos.ready():
            sleep(0.5)
        jobs_start_times = [None, None, job_dos_start_time]
        results_folder_names = [None, None, result_folder_name_dos]
else:
    if 'sqli' in SELECTED_ATTACKS['Inj'] and 'xmli' in SELECTED_ATTACKS['Inj']:
        while not job_sqli.ready() or not job_xmli.ready():
            sleep(0.5)
        jobs_start_times = [job_xmli_start_time, job_sqli_start_time, None]
        results_folder_names = [result_folder_name_xmli, result_folder_name_sqli, None]
    elif 'sqli' in SELECTED_ATTACKS['Inj']:
        while not job_sqli.ready():
            sleep(0.5)
        jobs_start_times = [None, job_sqli_start_time, None]
        results_folder_names = [None, result_folder_name_sqli, None]
    elif 'xmli' in SELECTED_ATTACKS['Inj']:
        while not job_xmli.ready():
            sleep(0.5)
        jobs_start_times = [job_xmli_start_time, None, None]
        results_folder_names = [result_folder_name_xmli, None, None]
    else:
        print("No attack selected !")
        jobs = False
if jobs:
    generate_reports(SELECTED_ATTACKS, WS_TYPE, ws_name, operation.name, jobs_start_times, results_folder_names)