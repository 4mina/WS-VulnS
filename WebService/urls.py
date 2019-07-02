from django.conf.urls import url
from . import views

app_name = 'WebService'

urlpatterns = [
    url(r'^$', views.IndexView.as_view(), name='index'),
    url(r'^about/$', views.AboutView.as_view(), name='about'),
    url(r'^documentation/$', views.DocumentationView.as_view(), name='documentation'),
]

