from django.conf.urls import url
from . import views

app_name = 'Attacks'


urlpatterns = [
    url(r'^(?P<ws_type>(soap|rest))/(?P<ws_id>[0-9]+)/(?P<op_id>[0-9]+)/attacks_selection/$',
        views.AttackCreationView.as_view(), name='attacks_choices'),
    url(r'^(?P<ws_type>(soap|rest))/(?P<ws_id>[0-9]+)/(?P<op_id>[0-9]+)/attacks_processing/$',
        views.AttacksProcessingView.as_view(), name='attacks_processing'),
    url(r'^(?P<ws_type>(soap|rest))/(?P<ws_id>[0-9]+)/(?P<op_id>[0-9]+)/attacks_processing/process-attacks/$',
        views.AttacksProcessingView.process_attacks, name='process_attacks'),
    url(r'^(?P<ws_type>(soap|rest))/(?P<ws_id>[0-9]+)/(?P<op_id>[0-9]+)/attacks_processing/get-task-info/$',
        views.AttacksProcessingView.get_task_info, name='get_task_info'),
    url(r'^(?P<ws_type>(soap|rest))/(?P<ws_id>[0-9]+)/(?P<op_id>[0-9]+)/attacks_processing/report/$',
        views.ReportView.as_view(), name='report'),
    url(r'^(?P<ws_type>(soap|rest))/(?P<ws_id>[0-9]+)/(?P<op_id>[0-9]+)/attacks_processing/report/(?P<filename>'
        r'[\w.]{0,256})/$', views.display_pdf, name='display_report_pdf'),
    url(r'^(?P<ws_type>(soap|rest))/(?P<ws_id>[0-9]+)/(?P<op_id>[0-9]+)/attacks_processing/report/log/(?P<filename>'
        r'[\w.]{0,256})/$', views.display_pdf, name='display_log_pdf'),
]
