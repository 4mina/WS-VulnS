from django.shortcuts import render, redirect
from django.views.generic import View, TemplateView
from WebService.forms import IndexForm
from WebService.models import WebService


class IndexView(View):
    template_name = 'WebService/index.html'
    form_class = IndexForm

    def get(self, request):
        form = self.form_class()
        return render(request, self.template_name, {'form': form})

    def post(self, request):
        form = self.form_class(request.POST, request.FILES)
        if form.is_valid():
            web_service = form.save()
            if web_service.description_url:
                if WebService.objects.filter(description_url=web_service.description_url):
                    web_service = WebService.objects.get(description_url=web_service.description_url)
                else:
                    web_service.save()
            elif web_service.description_file:
                if WebService.objects.filter(description_file=web_service.description_file):
                    web_service = WebService.objects.get(description_file=web_service.description_file.name)
                else:
                    web_service.save()
            if web_service.type == "SOAP":
                return redirect('SOAP:soap_client', web_service.id)
            else:
                return redirect('REST:rest_client', web_service.id)
        return render(request, self.template_name, {'form': form})


class AboutView(TemplateView):
    template_name = 'WebService/about.html'


class DocumentationView(TemplateView):
    template_name = 'WebService/documentation.html'
