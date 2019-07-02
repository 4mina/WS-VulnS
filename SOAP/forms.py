from django import forms

from collections import Mapping

import SOAP.wsdl_types as wsdl_types
from SOAP.models import Operation


class OperationForm(forms.ModelForm):
    class Meta:
        model = Operation
        exclude = ['name', 'endpoint', 'documentation', 'parameters', 'soap_action']

    def __init__(self, *args, **kwargs):
        self.soap_operation_id = kwargs.pop('soap_operation_id')
        super(OperationForm, self).__init__(*args, **kwargs)
        operation = Operation.objects.get(pk=self.soap_operation_id)
        if operation.parameters['input']:
            for name, info in operation.parameters['input'].items():
                field_type = info['type']
                if isinstance(field_type, Mapping):
                    if 'Enumeration' in field_type:
                        self.fields[name] = forms.ChoiceField(label=name, widget=forms.Select(), choices=set(
                            zip(field_type['Enumeration'], field_type['Enumeration'])), )
                    else:
                        self.fields[name] = forms.CharField(label=name, widget=forms.Textarea(attrs={'placeholder': field_type}))
                else:
                    field_type = field_type.lower()
                    if (field_type in wsdl_types.STRING_TYPES_LIST) or (field_type == 'anyuri'):
                        self.fields[name] = forms.CharField(label=name, max_length=200, widget=forms.TextInput(attrs={'placeholder': 'XSD : ' + field_type.capitalize()}))
                    elif (field_type =='base64binary') or (field_type =='hexbinary'):
                        self.fields[name] = forms.CharField(label=name, widget=forms.Textarea(attrs={'placeholder': 'XSD : ' + field_type.capitalize()}))
                    elif field_type == 'boolean':
                        self.fields[name] = forms.ChoiceField(label=name, widget=forms.Select(), choices=set(
                            zip(['true', 'false'], ['true', 'false'])))
                    elif field_type == 'int':
                        self.fields[name] = forms.IntegerField(label=name, min_value=wsdl_types.MIN_INT,
                                                               max_value=wsdl_types.MAX_INT)
                    elif field_type == 'short':
                        self.fields[name] = forms.IntegerField(label=name, min_value=wsdl_types.MIN_SHORT,
                                                               max_value=wsdl_types.MAX_SHORT)
                    elif field_type == 'byte':
                        self.fields[name] = forms.IntegerField(label=name, min_value=wsdl_types.MIN_BYTE,
                                                               max_value=wsdl_types.MAX_BYTE)
                    elif field_type == 'integer' or field_type == 'long':
                        self.fields[name] = forms.IntegerField(label=name, min_value=wsdl_types.MIN_LONG,
                                                               max_value=wsdl_types.MAX_LONG)
                    elif field_type == 'negativeinteger':
                        self.fields[name] = forms.IntegerField(label=name, min_value=wsdl_types.MIN_LONG, max_value=-1)
                    elif field_type == 'nonnegativeinteger':
                        self.fields[name] = forms.IntegerField(label=name, min_value=0, max_value=wsdl_types.MAX_LONG)
                    elif field_type == 'positiveinteger':
                        self.fields[name] = forms.IntegerField(label=name, min_value=1, max_value=wsdl_types.MAX_LONG)
                    elif field_type == 'nonpositiveinteger':
                        self.fields[name] = forms.IntegerField(label=name, min_value=wsdl_types.MIN_LONG, max_value=0)
                    elif field_type == 'unsignedlong':
                        self.fields[name] = forms.IntegerField(label=name, min_value=0,
                                                               max_value=wsdl_types.MAX_UNSIGNED_LONG)
                    elif field_type == 'unsignedint':
                        self.fields[name] = forms.IntegerField(label=name, min_value=0,
                                                               max_value=wsdl_types.MAX_UNSIGNED_INT)
                    elif field_type == 'unsignedshort':
                        self.fields[name] = forms.IntegerField(label=name, min_value=0,
                                                               max_value=wsdl_types.MAX_UNSIGNED_SHORT)
                    elif field_type == 'unsignedbyte':
                        self.fields[name] = forms.IntegerField(label=name, min_value=0,
                                                               max_value=wsdl_types.MAX_UNSIGNED_BYTE)
                    elif (field_type == 'decimal') or (field_type == 'float') or (field_type == 'double'):
                        self.fields[name] = forms.FloatField(label=name)
                    elif (field_type == 'gyearmonth') or (field_type == 'gmonthday') or (field_type == 'duration') or \
                            (field_type == 'daytimeduration') or (field_type == 'yearmonthduration') or \
                            (field_type == 'datetime') or (field_type == 'datetimestamp') or (field_type == 'time') or \
                            (field_type == 'date'):
                        self.fields[name] = forms.CharField(label=name, max_length=200, widget=forms.TextInput(attrs={'placeholder': 'XSD : ' + field_type.capitalize()}))
                    elif field_type == 'gday':
                        self.fields[name] = forms.ChoiceField(label=name, widget=forms.Select(), choices=set(
                            zip([x for x in range(1, 31)], [x for x in range(1, 31)])))
                    elif field_type == 'gmonth':
                        self.fields[name] = forms.ChoiceField(label=name, widget=forms.Select(), choices=set(
                            zip([x for x in range(1, 13)], [x for x in range(1, 13)])))
                    elif field_type == 'gyear':
                        self.fields[name] = forms.ChoiceField(label=name, widget=forms.Select(), choices=set(
                            zip([x for x in range(1900, 2019)], [x for x in range(1900, 2019)])))

    def clean(self):
        cleaned_data = super(OperationForm, self).clean()
        return cleaned_data

    def save(self, commit=True):
        operation = Operation.objects.get(id=self.soap_operation_id)

        return operation, self.cleaned_data
