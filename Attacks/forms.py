from django import forms
from betterforms.multiform import MultiForm

import os
import csv
from random import choice, randint, sample

from WS_VulnS.settings import BASE_DIR
from Attacks.choices import BILLION_LAUGHS, XML_BOMB_EXTERNAL, XMLB_TYPES, OVERSIZED_CONTENT, OVERSIZED_XML_TYPES, \
    OVERSIZED_PAYLOAD_TYPES, XML_INJECTION_TYPES, XML_INJECTION_PATTERNS_TYPES, \
    XML_INJECTION_SPECIAL_VALUES, XML_INJECTION_STRINGS_VALUES, XML_INJECTION_META_CHARACTERS, \
    SQLI_TYPES
from Attacks.models import XMLBombAttack, SQLiAttack, OversizedXMLAttack, OversizedPayloadAttack, XMLiAttack
from REST.models import Path


class XMLBombAttackForm(forms.Form):
    attack_selected = forms.BooleanField(label="Bombe XML", required=False)
    xmlb_type = forms.ChoiceField(label='Type de Bombe XML ', choices=XMLB_TYPES)
    xmlbint_payload = forms.CharField(label='' ''''Bombe XML avec référence locale''', widget=forms.Textarea)
    xmlbext_payload = forms.CharField(label='', widget=forms.Textarea, initial=XML_BOMB_EXTERNAL)
    xmlbbil_payload = forms.CharField(label='', widget=forms.Textarea)
    # number of entity calls in each entity
    num_recursion = forms.IntegerField(label='Nombre de récursions ')
    # number of declared entities
    num_entities = forms.IntegerField(label='Nombre d\'entités ')

    def __init__(self, *args, **kwargs):
        file = open(os.path.join(BASE_DIR, 'Attacks','Attacks_payloads', 'XML Bomb', 'Internal Entity.xml'), 'r')
        updated_initial = {'xmlbint_payload': file.read()}
        file.close()
        updated_initial.update({'xmlbbil_payload': BILLION_LAUGHS, 'num_recursion': 10, 'num_entities': 10})
        kwargs.update(initial=updated_initial)
        super(XMLBombAttackForm, self).__init__(*args, **kwargs)

    def save(self):
        # XML Bomb Internal Entity ref
        xmlbint = XMLBombAttack(type='IntEnt', payload=self.cleaned_data['xmlbint_payload'])
        # XML Bomb External Entity ref
        xmlbext = XMLBombAttack(type='ExtEnt', payload=self.cleaned_data['xmlbext_payload'])
        # bil attack but first check if num_recursion or num_entities are specified
        num_entities = self.cleaned_data['num_entities']
        num_recursion = self.cleaned_data['num_recursion']
        payload = self.cleaned_data['xmlbbil_payload']
        if payload == self.initial['xmlbbil_payload']:
            if (num_recursion != self.initial['num_recursion']) | (num_entities != self.initial['num_entities']):
                # generate the payload based on given values
                payload = self.generate_bil(num_entities, num_recursion)
        bil = XMLBombAttack(type='BIL', payload=payload)
        return xmlbint, xmlbext, bil

    def generate_bil(self, num_entities, num_recursion):
        bil = "<!DOCTYPE lolz [\n<!ENTITY lol0 \"lol\">\n"
        for i in range(1, num_entities):
            bil += "<!ENTITY lol" + str(i) + " \""
            for j in range(num_recursion):
                bil += "&lol" + str(i - 1) + ";"
            bil += "\">\n"
        bil += "]>\n<lolz>&lol" + str(i) + ";</lolz>"
        return bil


class OversizedXMLAttackForm(forms.Form):
    attack_selected = forms.BooleanField(label='Oversized XML', required=False)
    oversized_xml_type = forms.ChoiceField(label='Type de Oversized XML ', choices=OVERSIZED_XML_TYPES)
    oversized_attribute_content_payload = forms.CharField(label='Large contenu utilisé dans l\'attaque XML Oversized '
                                                                'Attribute Content ',
                                                          widget=forms.Textarea, initial=OVERSIZED_CONTENT)
    extra_long_names_payload = forms.CharField(label='Large contenu utilisé dans l\'attaque XML Extra Long Names ',
                                               widget=forms.Textarea, initial=OVERSIZED_CONTENT)
    number_characters = forms.IntegerField(label='Nombre de caractères ', initial=0)

    field_order = ['attack_selected', 'oversized_xml_type', 'number_characters', 'oversized_attribute_content_payload',
                   'extra_long_names_payload']

    # Get payload from one of the oversized files
    def get_payload_from_file(self, size):
        file_path = os.path.join(BASE_DIR, 'Attacks', 'Attacks_payloads', 'Oversized XML Payload',
                                 'Oversized_{size}MO.txt'.format(size=size))
        with open(file_path, 'r') as file:
            payload = file.read()
        file.close()

        return payload

    def generate_big_string(self, number_characters):
        return '?' * number_characters

    def save(self):
        number_characters = self.cleaned_data['number_characters']
        oversized_xml_type = self.cleaned_data['oversized_xml_type']
        oversized_xml = OversizedXMLAttack(type=oversized_xml_type)
        print(oversized_xml_type)

        if oversized_xml_type == 'OverAttrContent':
            oversized_attribute_content_payload = self.cleaned_data['oversized_attribute_content_payload']
            if oversized_attribute_content_payload == OVERSIZED_CONTENT:
                if number_characters == 0:
                    size = 10  # 10 MO by default
                    oversized_attribute_content_payload = self.get_payload_from_file(size)
                else:
                    oversized_attribute_content_payload = self.generate_big_string(number_characters)
            oversized_xml.payload = oversized_attribute_content_payload

        elif oversized_xml_type == 'LongNames':
            extra_long_names_payload = self.cleaned_data['extra_long_names_payload']
            if extra_long_names_payload == OVERSIZED_CONTENT:
                if number_characters == 0:
                    size = 10  # 10 MO by default
                    extra_long_names_payload = self.get_payload_from_file(size)
                else:
                    extra_long_names_payload = self.generate_big_string(number_characters)
            oversized_xml.payload = extra_long_names_payload

        return oversized_xml


class OversizedPayloadAttackForm(forms.Form):
    attack_selected = forms.BooleanField(label='Oversized Payload', required=False)
    oversized_payload_type = forms.ChoiceField(label='Type de Oversized Payload ', choices=OVERSIZED_PAYLOAD_TYPES)
    header_payload = forms.CharField(label='Large payload utilisée dans le SOAP Header ', widget=forms.Textarea,
                                     initial=OVERSIZED_CONTENT)
    body_payload = forms.CharField(label='Large payload utilisée dans SOAP Body ', widget=forms.Textarea,
                                   initial=OVERSIZED_CONTENT)
    envelope_payload = forms.CharField(label='Large payload utilisée dans SOAP Envelope ', widget=forms.Textarea,
                                       initial=OVERSIZED_CONTENT)
    number_characters = forms.IntegerField(label='Nombre de caractères ', initial=0)

    field_order = ['attack_selected', 'oversized_payload_type', 'number_characters', 'header_payload', 'body_payload'
                   'envelope_payload']

    # Get payload from one of the oversized files
    def get_payload_from_file(self, size):
        file_path = os.path.join(BASE_DIR, 'Attacks', 'Attacks_payloads', 'Oversized XML Payload',
                                 'Oversized_{size}MO.txt'.format(size=size))
        with open(file_path, 'r') as file:
            payload = file.read()
        file.close()

        return payload

    def generate_big_string(self, number_characters):
        return '?' * number_characters

    def save(self):
        number_characters = self.cleaned_data['number_characters']
        oversized_payload_type = self.cleaned_data['oversized_payload_type']
        oversized_payload = OversizedPayloadAttack(type=oversized_payload_type)

        if oversized_payload_type == 'Header':
            header_payload = self.cleaned_data['header_payload']
            if header_payload == OVERSIZED_CONTENT:
                if number_characters == 0:
                    size = 10  # 10 MO by default
                    header_payload = self.get_payload_from_file(size)
                else:
                    header_payload = self.generate_big_string(number_characters)
            oversized_payload.payload = header_payload

        elif oversized_payload_type == 'Body':
            body_payload = self.cleaned_data['body_payload']
            if body_payload == OVERSIZED_CONTENT:
                if number_characters == 0:
                    size = 10
                    body_payload = self.get_payload_from_file(size)
                else:
                    body_payload = self.generate_big_string(number_characters)
            oversized_payload.payload = body_payload

        elif oversized_payload_type == 'Envelope':
            envelope_payload = self.cleaned_data['envelope_payload']
            if envelope_payload == OVERSIZED_CONTENT:
                if number_characters == 0:
                    size = 10  # 10 MO by default
                    envelope_payload = self.get_payload_from_file(size)
                else:
                    envelope_payload = self.generate_big_string(number_characters)
            oversized_payload.payload = envelope_payload

        return oversized_payload


class XMLiAttackForm(forms.Form):
    attack_selected = forms.BooleanField(label='Injections XML', required=False)
    xml_injection_type = forms.ChoiceField(label='Type d\'injections XML ', choices=XML_INJECTION_TYPES)
    # xml_injection_patterns_type = forms.ChoiceField(label='Type de patterns ', choices=XML_INJECTION_PATTERNS_TYPES)
    deforming_patterns = forms.CharField(label='Injections de type Deforming ', widget=forms.Textarea)
    random_closing_tags_patterns = forms.CharField(label='Injections de type Random Closing Tags ',
                                                   widget=forms.Textarea)
    # special_values_patterns = forms.CharField(label='Patterns de type \'Special Values\' ', widget=forms.Textarea)
    nested_sql_patterns = forms.CharField(label='Injections de type Injection Nested SQL ', widget=forms.Textarea)
    nested_xpath_patterns = forms.CharField(label='Injections de type Injection Nested XPath ',
                                            widget=forms.Textarea)
    number_deforming = forms.IntegerField(label='Nombre d\'injections type Deforming ', initial=0)
    number_random_closing_tags = forms.IntegerField(label='Nombre d\'injections de type Random Closing Tags ',
                                                    initial=0)
    # number_special_values = forms.IntegerField(label='Nombre de patterns de type \'Special Values\' ', initial=0)
    number_nested_sql = forms.IntegerField(label='Nombre d\'injections de type Nested SQL ', initial=0)
    number_nested_xpath = forms.IntegerField(label='Nombre d\'injections de type Nested XPath ', initial=0)

    field_order = ['attack_selected', 'xml_injection_type', 'number_deforming', 'number_random_closing_tags',
                   'number_nested_sql', 'number_nested_xpath', 'deforming_patterns', 'random_closing_tags_patterns',
                   'nested_sql_patterns', 'nested_xpath_patterns']
    # field_order = ['attack_selected', 'xml_injection_type', 'number_deforming', 'number_random_closing_tags',
    #                'number_special_values', 'number_nested_sql', 'number_nested_xpath', 'deforming_patterns',
    #                'random_closing_tags_patterns', 'special_values_patterns', 'nested_sql_patterns',
    #                'nested_xpath_patterns']

    def __init__(self, *args, **kwargs):
        file = open(os.path.join(BASE_DIR, 'Attacks', 'Attacks_payloads', 'XMLi', 'Deforming', 'Deforming.txt'), 'r')
        deforming_patterns = file.read()
        file.close()
        file = open(os.path.join(BASE_DIR, 'Attacks', 'Attacks_payloads', 'XMLi', 'Random Closing Tags',
                                 'Random Closing Tags.txt'), 'r')
        random_closing_tags_patterns = file.read()
        file.close()
        #file = open(os.path.join(BASE_DIR, 'Attacks', 'Attacks_payloads', 'XMLi', 'Special Values',
        #                         'Special Values.txt'), 'r')
        #special_values_patterns = file.read()
        #file.close()
        file = open(os.path.join(BASE_DIR, 'Attacks', 'Attacks_payloads', 'XMLi', 'Nested XPath',
                                 'Nested XPath.txt'), 'r')
        nested_xpath_patterns = file.read()
        file.close()
        nested_sql_patterns = self.get_sql_injection_patterns_from_file()
        kwargs.update(initial={'deforming_patterns': deforming_patterns,
                               'random_closing_tags_patterns': random_closing_tags_patterns,
                               #'special_values_patterns': special_values_patterns,
                               'nested_sql_patterns': '\n'.join(nested_sql_patterns),
                               'nested_xpath_patterns': nested_xpath_patterns})
        super(XMLiAttackForm, self).__init__(*args, **kwargs)
        self.fields['number_nested_xpath'] = forms.IntegerField(label='Nombre d\'injections de type Nested XPath ',
                                                                initial=0, max_value=len(nested_xpath_patterns))

    def mutation_operator_deforming(self, tag_content):
        random_index = randint(0, len(tag_content) - 1)

        return tag_content[:random_index] + choice(XML_INJECTION_META_CHARACTERS) + tag_content[random_index:]

    def mutation_operator_random_closing_tags(self, tag_value, tag_content):
        if tag_content:
            random_index = randint(0, len(tag_content) - 1)
            return tag_content[:random_index] + '</' + tag_value + '>' + tag_content[random_index:]
        else:
            return '</' + tag_value + '>'

    def get_xml_injection_patterns_from_file(self):
        file_path = os.path.join(BASE_DIR, 'Attacks', 'Attacks_payloads', 'XMLi', 'Patterns.csv')
        with open(file_path, 'r') as file:
            patterns = [{key: value for key, value in row.items()} for row in csv.DictReader(file,
                                                                                             skipinitialspace=True)]
        file.close()

        return patterns

    def get_sql_injection_patterns_from_file(self):
        files_path = []
        # files_path.append(os.path.join(BASE_DIR, 'Attacks', 'Attacks_payloads', 'SQLi', 'Classic_SQLi',
        #                                'other_classic_sqli'))
        files_path.append(os.path.join(BASE_DIR, 'Attacks', 'Attacks_payloads', 'SQLi',
                                       'Illegal_logically incorrect queries',
                                       'Illegal_logically_incorrect_queries_minimal.txt'))
        files_path.append(os.path.join(BASE_DIR, 'Attacks', 'Attacks_payloads', 'SQLi', 'Piggy Backed',
                                       'Piggy Backed.txt'))
        files_path.append(os.path.join(BASE_DIR, 'Attacks', 'Attacks_payloads', 'SQLi', 'Tautology',
                                       'Tautology.txt'))
        files_path.append(os.path.join(BASE_DIR, 'Attacks', 'Attacks_payloads', 'SQLi', 'Union',
                                       'Union.txt'))

        patterns = []
        for file_path in files_path:
            with open(file_path, 'r') as file:
                patterns.extend([line.rstrip('\n') for line in file])
            file.close()

        return patterns

    def generate_pattern(self, xml_injection_pattern_type):
        if xml_injection_pattern_type == 'deforming':
            return self.mutation_operator_deforming(choice(XML_INJECTION_STRINGS_VALUES))

        elif xml_injection_pattern_type == 'random closing tags':
            return self.mutation_operator_random_closing_tags(choice(XML_INJECTION_STRINGS_VALUES),
                                                              choice(XML_INJECTION_STRINGS_VALUES))

        elif xml_injection_pattern_type == 'special values':
            return choice(XML_INJECTION_SPECIAL_VALUES)

        elif xml_injection_pattern_type == 'nested sql':
            return choice(self.get_sql_injection_patterns_from_file())

    def get_patterns(self, number_patterns, changed_patterns, inital_patterns, pattern_type):
        if changed_patterns == inital_patterns:
            if number_patterns != 0:
                number_initial_patterns = len(inital_patterns)
                print('Number initial')
                print(number_initial_patterns)
                if number_patterns > number_initial_patterns:
                    difference = number_patterns - number_initial_patterns
                    for i in range(difference):
                        changed_patterns.append(self.generate_pattern(pattern_type))
                elif number_patterns < number_initial_patterns:
                    changed_patterns = changed_patterns[:number_patterns]

        print('Final')
        print(changed_patterns)
        return changed_patterns

    def save(self):
        number_deforming = self.cleaned_data['number_deforming']
        number_random_closing_tags = self.cleaned_data['number_random_closing_tags']
        #number_special_values = self.cleaned_data['number_special_values']
        number_nested_sql = self.cleaned_data['number_nested_sql']
        number_nested_xpath = self.cleaned_data['number_nested_xpath']

        deforming_patterns = self.get_patterns(number_deforming,
                                               self.cleaned_data['deforming_patterns'].splitlines(),
                                               self.initial['deforming_patterns'].splitlines(), 'deforming')
        random_closing_tags_patterns = self.get_patterns(number_random_closing_tags,
                                                         self.cleaned_data['random_closing_tags_patterns'].
                                                         splitlines(), self.initial['random_closing_tags_patterns'].
                                                         splitlines(), 'random closing tags')
        #special_values_patterns = self.get_patterns(number_special_values,
        #                                           self.cleaned_data['special_values_patterns'].splitlines(),
        #                                          self.initial['special_values_patterns'].splitlines(),
        #                                         'special values')
        nested_sql_patterns = self.get_patterns(number_nested_sql,
                                                self.cleaned_data['nested_sql_patterns'].splitlines(),
                                                self.initial['nested_sql_patterns'].splitlines(), 'nested sql')
        nested_xpath_patterns = self.get_patterns(number_nested_xpath,
                                                  self.cleaned_data['nested_xpath_patterns'].splitlines(),
                                                  self.initial['nested_xpath_patterns'].splitlines(), 'nested xpath')

        xml_injection_malformed = XMLiAttack(type='Malformed')
        xml_injection_malformed.patterns = deforming_patterns + random_closing_tags_patterns #+ special_values_patterns

        xml_injection_replicating = XMLiAttack(type='Replicating')
        xml_injection_replicating.patterns = deforming_patterns + random_closing_tags_patterns + nested_sql_patterns + nested_xpath_patterns #+ special_values_patterns
        xml_injection_xpath = XMLiAttack(type='XPath')
        xml_injection_xpath.patterns = nested_xpath_patterns
        # elif xml_injection_type == 'NestedSQL':
        #     nested_sql_patterns = self.get_patterns(number_patterns,
        #                                             self.cleaned_data['nested_sql_patterns'].splitlines(),
        #                                             self.initial['nested_sql_patterns'].splitlines(), 'nested sql')
        #     xml_injection.patterns = nested_sql_patterns

        return xml_injection_malformed, xml_injection_replicating, xml_injection_xpath


class SQLiAttackForm(forms.Form):
    attack_selected = forms.BooleanField(label="Injections SQL", required=False)
    sqli_type = forms.ChoiceField(label='Types d\'injections SQL ', choices=SQLI_TYPES)
    tauto_patterns = forms.CharField(label='', widget=forms.Textarea)
    num_taut = forms.IntegerField(label='Nombre d\'injections de type Tautologie ')
    union_patterns = forms.CharField(label='', widget=forms.Textarea)
    num_union = forms.IntegerField(label='Nombre d\'injections de type Union ')
    piggyb_patterns = forms.CharField(label='', widget=forms.Textarea)
    num_piggyb = forms.IntegerField(label='Nombre d\'injections de type Piggy Backed ')
    incq_patterns = forms.CharField(label='', widget=forms.Textarea)
    num_incq = forms.IntegerField()

    def __init__(self, *args, **kwargs):
        file = open(os.path.join(BASE_DIR, 'Attacks', 'Attacks_payloads', 'SQLi', 'Tautology', 'Tautology.txt'), 'r')
        updated_initial = {'tauto_patterns': file.read()}
        updated_initial.update({'num_taut': updated_initial['tauto_patterns'].splitlines().__len__()})
        file.close()
        file = open(os.path.join(BASE_DIR, 'Attacks', 'Attacks_payloads', 'SQLi', 'Union', 'Union.txt'), 'r')
        updated_initial.update({'union_patterns': file.read()})
        updated_initial.update({'num_union': updated_initial['union_patterns'].splitlines().__len__()})
        file.close()
        file = open(os.path.join(BASE_DIR, 'Attacks', 'Attacks_payloads', 'SQLi', 'Piggy Backed', 'Piggy Backed.txt'), 'r')
        updated_initial.update({'piggyb_patterns': file.read()})
        updated_initial.update({'num_piggyb': updated_initial['piggyb_patterns'].splitlines().__len__()})
        file.close()
        file = open(os.path.join(BASE_DIR, 'Attacks', 'Attacks_payloads', 'SQLi', 'Illegal_logically incorrect queries', 'Illegal_logically_incorrect_queries_minimal.txt'), 'r')
        updated_initial.update({'incq_patterns': file.read()})
        file.close()
        file = open(os.path.join(BASE_DIR,'Attacks', 'Attacks_payloads', 'SQLi', 'Illegal_logically incorrect queries', 'Illegal_logically_incorrect_queries.txt'), 'r')
        max_value = len(file.readlines())
        file.close()
        updated_initial.update({'num_incq': updated_initial['incq_patterns'].splitlines().__len__()})
        kwargs.update(initial=updated_initial)
        super(SQLiAttackForm, self).__init__(*args, **kwargs)
        self.fields['num_incq'] = forms.IntegerField(max_value=max_value, label='Nombre d\'injections de type Illegal / '
                                                                                'logically incorrect queries ')

    def get_sqli_patterns(self, sqli_type, initial_patterns, current_patterns, initil_num, current_num):
        if current_patterns == initial_patterns:
            if current_num > initil_num:
                # Get patterns from the ones generated with grammar
                if sqli_type == 'Taut':
                    patterns_file = os.path.join(BASE_DIR, 'Attacks', 'Attacks_payloads', 'SQLi', 'Tautology', 'tautology_sqli_generated_from_grammar.txt')
                elif sqli_type == 'Union':
                    patterns_file = os.path.join(BASE_DIR, 'Attacks', 'Attacks_payloads', 'SQLi', 'Union', 'union_sqli_generated_from_grammar.txt')
                elif sqli_type == 'PiggyB':
                    patterns_file = os.path.join(BASE_DIR, 'Attacks', 'Attacks_payloads', 'SQLi', 'Piggy Backed', 'piggy_backed_sqli_generated_from_grammar.txt')
                elif sqli_type == 'IncQ':
                    patterns_file = os.path.join(BASE_DIR, 'Attacks', 'Attacks_payloads', 'SQLi', 'Illegal_logically incorrect queries', 'Illegal_logically_incorrect_queries.txt')
                with open(patterns_file) as f:
                    current_patterns += sample(f.readlines(), (current_num - initil_num))
                    for i in range(len(current_patterns)):
                        if i <= len(current_patterns)/3:
                            current_patterns[i] = ' '.join(format(ord(x), 'b') for x in current_patterns[i])
                        elif len(current_patterns)/3 < i <= 2*len(current_patterns)/3:
                            current_patterns[i] = '%'.join(x.encode().hex() for x in current_patterns[i])
                f.close()
            elif current_num < initil_num:
                current_patterns = initial_patterns[:current_num]
        return current_patterns

    def save(self):
        taut = SQLiAttack(type='Taut', patterns=self.get_sqli_patterns('Taut', self.initial['tauto_patterns'].splitlines(),
                                                                       self.cleaned_data['tauto_patterns'].splitlines(),self.initial['num_taut'],
                                                                       self.cleaned_data['num_taut']))
        union = SQLiAttack(type='Union', patterns=self.get_sqli_patterns('Union', self.initial['union_patterns'].splitlines(),
                                                                       self.cleaned_data['union_patterns'].splitlines(),self.initial['num_union'],
                                                                       self.cleaned_data['num_union']))
        piggyb = SQLiAttack(type='PiggyB', patterns=self.get_sqli_patterns('PiggyB', self.initial['piggyb_patterns'].splitlines(),
                                                                       self.cleaned_data['piggyb_patterns'].splitlines(),self.initial['num_piggyb'],
                                                                       self.cleaned_data['num_piggyb']))
        incq = SQLiAttack(type='IncQ', patterns=self.get_sqli_patterns('IncQ', self.initial['incq_patterns'].splitlines(),
                                                                       self.cleaned_data['incq_patterns'].splitlines(),self.initial['num_incq'],
                                                                       self.cleaned_data['num_incq']))
        return taut, union, piggyb, incq


class AttackCreationMultiForm(MultiForm):
    form_classes = {}

    # get_form_kwargs does not work with django betterforms (multiform) so we add as argument kwargs of the view
    def __init__(self, kwargs_view, *args, **kwargs):
        if kwargs_view.get('ws_type', ) == 'rest':
            # check if the selected path can hold XML data so that to test XML attacks
            path = Path.objects.get(id=kwargs_view.get("op_id", ))
            if path.get_methods_accept_xml():
                self.form_classes = {
                    'xmlb': XMLBombAttackForm,
                    'overxml': OversizedXMLAttackForm,
                    'overpayload': OversizedPayloadAttackForm,
                    'xmli': XMLiAttackForm,
                    'sqli': SQLiAttackForm
                }
                super(AttackCreationMultiForm, self).__init__(*args, **kwargs)
                self.forms['overpayload'].fields.pop('envelope_payload')
                self.forms['overpayload'].fields.pop('header_payload')
                self.forms['overpayload'].fields.get('oversized_payload_type').choices = [OVERSIZED_PAYLOAD_TYPES[1]]
            else:
                self.form_classes = {
                    'sqli': SQLiAttackForm
                }
                super(AttackCreationMultiForm, self).__init__(*args, **kwargs)
        else:
            self.form_classes = {
                'xmlb': XMLBombAttackForm,
                'overxml': OversizedXMLAttackForm,
                'overpayload': OversizedPayloadAttackForm,
                'xmli': XMLiAttackForm,
                'sqli': SQLiAttackForm
            }
            super(AttackCreationMultiForm, self).__init__(*args, **kwargs)

    def clean(self):
        cleaned_data = super(AttackCreationMultiForm, self).clean()
        if self.form_classes.get('xmlb') and self.form_classes.get('overxml') and self.form_classes.get(
                'overpayload') and self.form_classes.get('xmli'):
            xmlb_attack_selected = cleaned_data['xmlb']['attack_selected']
            overxml_attack_selected = cleaned_data['overxml']['attack_selected']
            overpayload_attack_selected = cleaned_data['overpayload']['attack_selected']
            xmli_attack_selected = cleaned_data['xmli']['attack_selected']
        # the form does not exist so we give it the value True so as not to make the condition depends
        # only on existing forms
        else:
            xmlb_attack_selected = False
            overxml_attack_selected = False
            overpayload_attack_selected = False
            xmli_attack_selected = False
        sqli_attack_selected = cleaned_data['sqli']['attack_selected']
        if (not xmlb_attack_selected) and (not overxml_attack_selected) and (not overpayload_attack_selected) and (
        not xmli_attack_selected) and (not sqli_attack_selected):
            raise forms.ValidationError(message='Choisissez au moins une attaque à tester !',
                                        code='no_attack_selected_error')
        return cleaned_data
