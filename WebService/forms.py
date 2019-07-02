from django import forms

from SOAP.models import SoapWebService
from WebService.models import WebService
from REST.models import RestWebService


class IndexForm(forms.ModelForm):
    class Meta:
        model = WebService
        fields = ['type', 'description_url', 'description_file']

    def clean(self):
        cleaned_data = super(IndexForm, self).clean()
        type = cleaned_data.get('type', )
        description_file = cleaned_data.get('description_file', )
        description_url = cleaned_data.get('description_url', )
        if (description_url == "") & (not description_file):
            raise forms.ValidationError(message='Veuillez entrer l\'URL ou charger le fichier de description', code='empty_description')
        if type == "SOAP":
            if description_file:
                if (not description_file.name.endswith("wsdl")) & (not description_file.name.endswith("WSDL")):
                    raise forms.ValidationError(message='La description jointe ne correspond pas au type SOAP',
                                                code='soap_description_not_valid')
            elif (not description_url.endswith("wsdl")) & (not description_url.endswith("WSDL")):
                    raise forms.ValidationError(message='La description jointe ne correspond pas au type SOAP',
                                                code='soap_description_not_valid')
            else:
                print("SOAP OK")
        else:
            if description_file:
                if (not description_file.name.endswith("yaml")) & (not description_file.name.endswith("yml")):
                    raise forms.ValidationError(message='La description jointe ne correspond pas au type REST',
                                            code='rest_description_not_valid')
            elif (not description_url.endswith("yaml")) & (not description_url.endswith("yml")):
                raise forms.ValidationError(message='La description jointe ne correspond pas au type REST',
                                            code='rest_description_not_valid')
            else:
                print("REST OK")
        return cleaned_data

    def save(self, **kwargs):
        # check the WS type to create the right object
        if self.cleaned_data['type'] == "SOAP":
            web_service = SoapWebService()
        else:
            web_service = RestWebService()
        web_service.type = self.cleaned_data['type']
        if self.cleaned_data.get('description_url', '') == "":
            web_service.description_file = self.cleaned_data.get('description_file', '')
        else:
            web_service.description_url = self.cleaned_data.get('description_url', '')
        return web_service
